// Package controller — IssuerReconciler is the Certificate reconciler.
// It dispatches to the right provider based on IssuerRef.Kind, fetches
// the secret, parses the payload, and writes the k8s Secret.
// ponytail: provider selection lives in dispatchProvider; everything else
// is provider-agnostic.
package controller

import (
	"context"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
		ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"

	api "github.com/arindraaribudi/cert-manager-ext-issuer-secret-manager/api/v1alpha1"
)

// SecretResolver fetches and returns the raw JSON payload bytes from the
// configured cloud provider, given a spec + secret-manager-side ref.
// Each cloud package's fake + real client implements this signature via a
// thin adapter. Today the real AWS/GCP/Tencent clients don't yet satisfy
// this shape (T9/T10 return raw bytes; T11 stub) — that's OK, the wiring
// in app.go will adapt them. The reconciler only depends on this interface.
type SecretResolver func(ctx context.Context, ref string) ([]byte, error)

// IssuerReconciler reconciles Certificate resources by fetching TLS material
// from the configured cloud provider.
type IssuerReconciler struct {
	client.Client
	Scheme *runtime.Scheme

	// ProviderResolvers maps Kind name → SecretResolver. Set at wire-up time
	// by internal/app/app.go so this controller stays provider-agnostic.
	ProviderResolvers map[string]SecretResolver

	// PayloadKeysFromIssuer returns the PayloadKeys for a given IssuerKind +
	// IssuerName + Certificate namespace. Set at wire-up time. Allows the
	// reconciler to read configurable field names without knowing the issuer
	// kind shape.
	PayloadKeysFromIssuer func(ctx context.Context, cert *cmapi.Certificate) (api.PayloadKeys, error)

	// CertManagerNamespace is the fallback ns for ClusterIssuer secretRefs.
	// ponytail: matches spec §3 — namespaced Issuer resolves empty ns from
	// Certificate ns; ClusterIssuer from this flag.
	CertManagerNamespace string
}

func (r *IssuerReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var cert cmapi.Certificate
	if err := r.Get(ctx, req.NamespacedName, &cert); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// 1. Annotation present?
	ref, ok := SecretName(&cert)
	if !ok {
		SetReady(&cert, false, "MissingSecretRef", "annotation cert-manager.io/secret-manager-secret-name is required")
		_ = r.Status().Update(ctx, &cert)
		return ctrl.Result{}, nil
	}

	// 2. Resolve provider + fetch
	resolver, kind := r.lookupResolver(cert.Spec.IssuerRef.Kind)
	if resolver == nil {
		SetReady(&cert, false, "InvalidSpec", fmt.Sprintf("no provider registered for kind %q", cert.Spec.IssuerRef.Kind))
		_ = r.Status().Update(ctx, &cert)
		return ctrl.Result{}, nil
	}
	_ = kind

	payload, err := resolver(ctx, ref)
	if err != nil {
		SetReady(&cert, false, "SourceMissing", err.Error())
		_ = r.Status().Update(ctx, &cert)
		return ctrl.Result{}, nil
	}

	// 3. Parse payload
	keys, err := r.PayloadKeysFromIssuer(ctx, &cert)
	if err != nil {
		SetReady(&cert, false, "InvalidSpec", err.Error())
		_ = r.Status().Update(ctx, &cert)
		return ctrl.Result{}, nil
	}
	parsed, err := Extract(payload, keys)
	if err != nil {
		SetReady(&cert, false, "InvalidPayload", err.Error())
		_ = r.Status().Update(ctx, &cert)
		return ctrl.Result{}, nil
	}

	// 4. Build k8s Secret
	secretTemplate := corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: cert.Spec.SecretName,
			Annotations: map[string]string{
				// ponytail: cert-manager refuses to trust an existing Secret
				// unless they prove it came from the issuer named in the
				// Certificate spec — otherwise it reports IncorrectIssuer.
				"cert-manager.io/issuer-name": cert.Spec.IssuerRef.Name,
				"cert-manager.io/issuer-kind": cert.Spec.IssuerRef.Kind,
			},
			OwnerReferences: []metav1.OwnerReference{
				*metav1.NewControllerRef(&cert, schema.GroupVersionKind{
					Group: "cert-manager.io", Version: "v1", Kind: "Certificate",
				}),
			},
		},
		Type: corev1.SecretTypeTLS,
		Data: map[string][]byte{
			corev1.TLSCertKey:       parsed.Certificate,
			corev1.TLSPrivateKeyKey: parsed.PrivateKey,
		},
	}
	if len(parsed.Chain) > 0 {
		secretTemplate.Data[corev1.ServiceAccountRootCAKey] = parsed.Chain
	}

	// 4a. Resolve target namespaces.
	// Namespaced Issuer → just the Certificate's ns.
	// ClusterIssuer-kind → every non-terminating namespace in the cluster.
	targets, err := r.targetNamespaces(ctx, &cert)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("list namespaces: %w", err)
	}

	for _, ns := range targets {
		secret := secretTemplate.DeepCopy()
		secret.Namespace = ns
		if err := r.writeSecret(ctx, secret); err != nil {
			return ctrl.Result{}, err
		}
	}

	// 4b. Sign the matching CertificateRequest so cert-manager's issuing
	// controller can proceed. Best-effort: if no CR exists yet, the issuing
	// controller will create one on its next reconcile and we'll sign it then.
	if err := r.signCertificateRequest(ctx, &cert, parsed.Certificate, parsed.Chain); err != nil {
		SetReady(&cert, false, "SignCRFailed", err.Error())
		_ = r.Status().Update(ctx, &cert)
		return ctrl.Result{}, nil
	}

	// 5. Clear force-sync if set
	if IsForceSyncSet(&cert) {
		ClearForceSync(&cert)
		_ = r.Update(ctx, &cert)
	}

	SetReady(&cert, true, "Synced", "secret reconciled from cloud")
	_ = r.Status().Update(ctx, &cert)
	return ctrl.Result{}, nil
}

// signCertificateRequest finds the CR cert-manager created for this
// Certificate (named "<cert-name>-<revision>", revision starts at 1) and
// marks it Ready with the fetched cert bytes. cert-manager's issuing
// controller then assembles/refreshes the target Secret.
func (r *IssuerReconciler) signCertificateRequest(ctx context.Context, cert *cmapi.Certificate, certPEM, chainPEM []byte) error {
	crName := cert.Name + "-1"
	var cr cmapi.CertificateRequest
	err := r.Get(ctx, types.NamespacedName{Name: crName, Namespace: cert.Namespace}, &cr)
	if apierrors.IsNotFound(err) {
		// CR not created yet — issuing controller will create it; we'll sign on next reconcile.
		return nil
	}
	if err != nil {
		return fmt.Errorf("get CertificateRequest %s/%s: %w", cert.Namespace, crName, err)
	}
	SetCRReady(&cr, certPEM, chainPEM, "Signed", "signed by cert-manager-ext-issuer-secret-manager")
	if err := r.Status().Update(ctx, &cr); err != nil {
		return fmt.Errorf("update CertificateRequest %s/%s status: %w", cert.Namespace, crName, err)
	}
	return nil
}

// lookupResolver returns the registered SecretResolver for the given Kind,
// or nil if the kind is unknown. Used by Reconcile to dispatch by kind
// (provider is encoded in the Kind name in single-group architecture).
func (r *IssuerReconciler) lookupResolver(kind string) (SecretResolver, string) {
	if r.ProviderResolvers == nil {
		return nil, ""
	}
	resolver, ok := r.ProviderResolvers[kind]
	if !ok {
		return nil, ""
	}
	return resolver, kind
}

// targetNamespaces returns the namespaces the cert's TLS Secret should be
// written into. Namespaced Issuer → just cert.Namespace. ClusterIssuer-kind →
// every non-terminating namespace in the cluster (fan-out).
func (r *IssuerReconciler) targetNamespaces(ctx context.Context, cert *cmapi.Certificate) ([]string, error) {
	if !strings.HasSuffix(cert.Spec.IssuerRef.Kind, "ClusterIssuer") {
		return []string{cert.Namespace}, nil
	}
	var nsl corev1.NamespaceList
	if err := r.List(ctx, &nsl); err != nil {
		return nil, err
	}
	out := make([]string, 0, len(nsl.Items))
	for _, ns := range nsl.Items {
		if ns.Status.Phase == corev1.NamespaceTerminating {
			continue
		}
		out = append(out, ns.Name)
	}
	return out, nil
}

// writeSecret creates or updates the given Secret.
func (r *IssuerReconciler) writeSecret(ctx context.Context, secret *corev1.Secret) error {
	if err := r.Update(ctx, secret); err != nil {
		if apierrors.IsNotFound(err) {
			return r.Create(ctx, secret)
		}
		return fmt.Errorf("update secret %s/%s: %w", secret.Namespace, secret.Name, err)
	}
	return nil
}
