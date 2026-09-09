// Package controller — IssuerReconciler is the Certificate reconciler.
// It dispatches to the right provider based on IssuerRef.Kind, fetches
// the secret, parses the payload, and writes the k8s Secret.
// ponytail: provider selection lives in dispatchProvider; everything else
// is provider-agnostic.
package controller

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
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
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      cert.Spec.SecretName,
			Namespace: cert.Namespace,
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
		secret.Data[corev1.ServiceAccountRootCAKey] = parsed.Chain
	}

	if err := r.Update(ctx, secret); err != nil {
		if apierrors.IsNotFound(err) {
			if err := r.Create(ctx, secret); err != nil {
				return ctrl.Result{}, fmt.Errorf("create secret: %w", err)
			}
		} else {
			return ctrl.Result{}, fmt.Errorf("update secret: %w", err)
		}
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
