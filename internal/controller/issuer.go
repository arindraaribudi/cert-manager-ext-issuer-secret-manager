// Package controller — IssuerReconciler is the Certificate reconciler.
// It dispatches to the right provider based on IssuerRef.Kind, fetches
// the secret, parses the payload, and writes the k8s Secret.
// ponytail: provider selection lives in dispatchProvider; everything else
// is provider-agnostic.
package controller

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"
	"time"

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

// RequeueAfterError lives in log.go (shared across reconcilers).

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

	// IssuerConfigFromIssuer returns the IssuerConfig (PayloadKeys +
	// NamespaceFilter) for a given IssuerKind + IssuerName + Certificate
	// namespace. Set at wire-up time. Allows the reconciler to read
	// configurable settings without knowing the issuer kind shape.
	IssuerConfigFromIssuer func(ctx context.Context, cert *cmapi.Certificate) (api.IssuerConfig, error)

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
		_ = MarkCertDrift(ctx, r.Client, &cert, "MissingSecretRef", "annotation cert-manager.io/secret-manager-secret-name is required")
		return RequeueAfterError(ctx, fmt.Errorf("annotation cert-manager.io/secret-manager-secret-name is required"),
			"secret-manager: missing annotation",
			"cert", req.String()), nil
	}

	// 2. Resolve provider + fetch
	resolver, kind := r.lookupResolver(cert.Spec.IssuerRef.Kind)
	if resolver == nil {
		_ = MarkCertDrift(ctx, r.Client, &cert, "InvalidSpec", fmt.Sprintf("no provider registered for kind %q", cert.Spec.IssuerRef.Kind))
		return RequeueAfterError(ctx, fmt.Errorf("no provider registered for kind %q", cert.Spec.IssuerRef.Kind),
			"secret-manager: unknown issuer kind",
			"cert", req.String(), "issuerRef", fmt.Sprintf("%s/%s", cert.Spec.IssuerRef.Group, cert.Spec.IssuerRef.Kind)), nil
	}
	_ = kind

	payload, err := resolver(ctx, ref)
	if err != nil {
		_ = MarkCertDrift(ctx, r.Client, &cert, "SourceMissing", err.Error())
		return RequeueAfterError(ctx, err, "secret-manager: fetch payload",
			"cert", req.String(), "secretRef", ref, "kind", kind), nil
	}

	// 3. Parse payload
	cfg, err := r.IssuerConfigFromIssuer(ctx, &cert)
	if err != nil {
		_ = MarkCertDrift(ctx, r.Client, &cert, "InvalidSpec", err.Error())
		return RequeueAfterError(ctx, err, "secret-manager: load issuer config",
			"cert", req.String()), nil
	}
	parsed, err := Extract(payload, cfg.PayloadKeys)
	if err != nil {
		_ = MarkCertDrift(ctx, r.Client, &cert, "InvalidPayload", err.Error())
		return RequeueAfterError(ctx, err, "secret-manager: parse payload",
			"cert", req.String(), "secretRef", ref, "kind", kind), nil
	}

	// 4. Build k8s Secret
	secretTemplate := corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: cert.Spec.SecretName,
			Annotations: map[string]string{
				// ponytail: cert-manager refuses to trust an existing Secret
				// unless all three annotations match the Certificate's
				// IssuerRef — otherwise it reports IncorrectIssuer. A missing
				// issuer-group defaults to "cert-manager.io", which silently
				// breaks every external issuer (this project's whole point).
				"cert-manager.io/issuer-name":  cert.Spec.IssuerRef.Name,
				"cert-manager.io/issuer-kind":  cert.Spec.IssuerRef.Kind,
				"cert-manager.io/issuer-group": issuerGroup(cert.Spec.IssuerRef.Group),
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
	for k, v := range CertAnnotations(parsed.Certificate) {
		secretTemplate.Annotations[k] = v
	}

	// 4a. Resolve target namespaces.
	// Namespaced Issuer → just the Certificate's ns.
	// ClusterIssuer-kind → every non-terminating namespace in the cluster.
	targets, err := r.targetNamespaces(ctx, &cert, cfg.NamespaceFilter)
	if err != nil {
		_ = MarkCertDrift(ctx, r.Client, &cert, "NamespaceListFailed", err.Error())
		return RequeueAfterError(ctx, fmt.Errorf("list namespaces: %w", err), "secret-manager: list namespaces",
			"cert", req.String()), nil
	}

	for _, ns := range targets {
		secret := secretTemplate.DeepCopy()
		secret.Namespace = ns
		// Kubernetes forbids cross-namespace owner references — a namespaced
		// owner ref to an object in another namespace is treated as absent,
		// so the GC deletes the dependent right after it's created. Only the
		// copy in the Certificate's own namespace can carry the owner ref.
		if ns == cert.Namespace {
			secret.OwnerReferences = []metav1.OwnerReference{
				*metav1.NewControllerRef(&cert, schema.GroupVersionKind{
					Group: "cert-manager.io", Version: "v1", Kind: "Certificate",
				}),
			}
		}
		if err := r.writeSecret(ctx, secret); err != nil {
			_ = MarkCertDrift(ctx, r.Client, &cert, "SecretWriteFailed", err.Error())
			return RequeueAfterError(ctx, err, "secret-manager: write secret",
				"cert", req.String(), "namespace", ns, "secretName", cert.Spec.SecretName), nil
		}
	}

	// 4b. Sign the matching CertificateRequest so cert-manager's issuing
	// controller can proceed. Best-effort: if no CR exists yet, the issuing
	// controller will create one on its next reconcile and we'll sign it then.
	if err := r.signCertificateRequest(ctx, &cert, parsed.Certificate, parsed.Chain); err != nil {
		_ = MarkCertDrift(ctx, r.Client, &cert, "SignCRFailed", err.Error())
		return RequeueAfterError(ctx, err, "secret-manager: sign CertificateRequest",
			"cert", req.String()), nil
	}

	// 5. Clear force-sync if set
	if IsForceSyncSet(&cert) {
		ClearForceSync(&cert)
		_ = r.Update(ctx, &cert)
	}

	_ = ClearCertDrift(ctx, r.Client, &cert, "Synced", "secret reconciled from cloud")
	if err := r.setReady(ctx, &cert, true, "Synced", "secret reconciled from cloud"); err != nil {
		return RequeueAfterError(ctx, err, "secret-manager: setReady Synced",
			"cert", req.String()), nil
	}
	return ctrl.Result{}, nil
}

// setReady updates the Ready condition via a merge patch on the status
// subresource. Patches don't bump the main resourceVersion, so cert-manager's
// trigger-loop Update on the same Certificate won't race with us on
// optimistic locking — same fix as tencentcert + awscert controllers. Kills
// the per-minute Ready False→True churn in cert-manager core.
func (r *IssuerReconciler) setReady(ctx context.Context, cert *cmapi.Certificate, ok bool, reason, msg string) error {
	original := cert.DeepCopy()
	SetReady(cert, ok, reason, msg)
	return r.Status().Patch(ctx, cert, client.MergeFrom(original))
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
// every non-terminating namespace in the cluster (fan-out), narrowed by
// filter.Allow/Deny when set. Allow wins if both are set; neither set means
// every namespace.
func (r *IssuerReconciler) targetNamespaces(ctx context.Context, cert *cmapi.Certificate, filter api.NamespaceFilter) ([]string, error) {
	return TargetNamespaces(ctx, r.Client, cert, filter)
}

// TargetNamespaces is the package-level fan-out helper. Exported so the
// awscert + tencentcert controllers can reuse the same logic. See method
// for behavior.
func TargetNamespaces(ctx context.Context, c client.Client, cert *cmapi.Certificate, filter api.NamespaceFilter) ([]string, error) {
	if !strings.HasSuffix(cert.Spec.IssuerRef.Kind, "ClusterIssuer") {
		return []string{cert.Namespace}, nil
	}
	var nsl corev1.NamespaceList
	if err := c.List(ctx, &nsl); err != nil {
		return nil, err
	}
	allow := toSet(filter.Allow)
	deny := toSet(filter.Deny)
	out := make([]string, 0, len(nsl.Items))
	for _, ns := range nsl.Items {
		if ns.Status.Phase == corev1.NamespaceTerminating {
			continue
		}
		if len(allow) > 0 && !allow[ns.Name] {
			continue
		}
		if len(allow) == 0 && deny[ns.Name] {
			continue
		}
		out = append(out, ns.Name)
	}
	return out, nil
}

func toSet(names []string) map[string]bool {
	if len(names) == 0 {
		return nil
	}
	set := make(map[string]bool, len(names))
	for _, n := range names {
		set[n] = true
	}
	return set
}

// issuerGroup returns the group to stamp on the issued Secret. Empty
// IssuerRef.Group (the cert-manager built-in issuer case) defaults to
// "cert-manager.io" — that's what cert-manager itself assumes when the
// annotation is missing, and matching it here keeps the round-trip
// consistent for both built-in and external issuers.
func issuerGroup(g string) string {
	if g == "" {
		return "cert-manager.io"
	}
	return g
}

// certAnnotations parses the leaf cert and returns the DNS-names/validity
// annotations cert-manager itself stamps on Secrets it owns directly
// (cert-manager.io/{common-name,alt-names,not-before,not-after}). Returns
// nil on parse failure — these are informational, not required for the
// Secret to function as TLS material.
func CertAnnotations(certPEM []byte) map[string]string {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil
	}
	out := map[string]string{
		"cert-manager.io/common-name": leaf.Subject.CommonName,
		"cert-manager.io/not-before":  leaf.NotBefore.UTC().Format(time.RFC3339),
		"cert-manager.io/not-after":   leaf.NotAfter.UTC().Format(time.RFC3339),
	}
	if len(leaf.DNSNames) > 0 {
		out["cert-manager.io/alt-names"] = strings.Join(leaf.DNSNames, ",")
	}
	return out
}

// writeSecret creates or updates the given Secret.
func (r *IssuerReconciler) writeSecret(ctx context.Context, secret *corev1.Secret) error {
	return WriteSecret(ctx, r.Client, secret)
}

// WriteSecret creates or updates the given Secret, but skips the API call
// when the existing Secret already carries the same Data + Annotations + Type.
// Exported so awscert + tencentcert can reuse.
//
// ponytail: the unconditional Update pattern bumps Secret.resourceVersion every
// reconcile even when nothing changed. cert-manager core watches Secrets and
// re-enqueues the owning Certificate on rv bump — its trigger-loop then
// flips Ready False→True every minute (conditions.go:201 spam). Comparing
// payload bytes before the Patch makes the reconcile a true no-op when the
// cloud cert hasn't rotated.
func WriteSecret(ctx context.Context, c client.Client, secret *corev1.Secret) error {
	existing := &corev1.Secret{}
	err := c.Get(ctx, client.ObjectKeyFromObject(secret), existing)
	if apierrors.IsNotFound(err) {
		return c.Create(ctx, secret)
	}
	if err != nil {
		return fmt.Errorf("get secret %s/%s: %w", secret.Namespace, secret.Name, err)
	}
	if secretPayloadEqual(existing, secret) {
		return nil
	}
	// Apply desired state onto the existing object (preserves rv + uid +
	// non-listed fields), then merge-patch. JSON merge replaces annotations
	// and data wholesale on Secrets — fine, that's what we want here.
	original := existing.DeepCopy()
	existing.Data = secret.Data
	existing.Type = secret.Type
	existing.Annotations = secret.Annotations
	existing.Labels = secret.Labels
	if len(secret.OwnerReferences) > 0 {
		existing.OwnerReferences = secret.OwnerReferences
	}
	return c.Patch(ctx, existing, client.MergeFrom(original))
}

// secretPayloadEqual reports whether two Secrets carry the same payload that
// cert-manager (and consumers) actually read. resourceVersion, uid, labels
// and managedFields intentionally ignored.

// Drift annotations stamped on the target Secret when the cloud source is
// unreachable. cert-manager owns the Secret payload (we write it), but we
// own these three annotations — they let operators see drift without us
// deleting the Secret and breaking consumers that mount it.
const (
	AnnotationExternalIssuerDriftReason  = "external-issuer.cert-manager.io/drift-reason"
	AnnotationExternalIssuerDriftMessage = "external-issuer.cert-manager.io/drift-message"
	AnnotationExternalIssuerDriftAt      = "external-issuer.cert-manager.io/drift-at"
)

// MarkSecretDrift stamps the target Secret with the last source error so
// operators see drift without us removing it (and breaking any Deployment
// or Ingress mounting it). No-op when annotations already match the new
// error — avoids Secret rv bumps and cert-manager trigger storms. Returns
// nil on a missing Secret (nothing to mark).

// markCertDrift records drift on both the Secret (annotations) and the
// Certificate (ExternalIssuerSynced=False condition) so operators see it
// from either side. One helper per error path keeps call-sites to a
// single line. Returns the first error from either operation; callers
// decide whether to log/swallow.
func MarkCertDrift(ctx context.Context, c client.Client, cert *cmapi.Certificate, reason, msg string) error {
	if err := MarkSecretDrift(ctx, c, cert, reason, msg); err != nil {
		return err
	}
	original := cert.DeepCopy()
	SetExternalIssuerSynced(cert, false, reason, msg)
	return c.Status().Patch(ctx, cert, client.MergeFrom(original))
}

// clearCertDrift removes drift markers after a successful sync. Both the
// Secret annotations and the Certificate condition are reset. Pair this
// with setReady(True) so Ready and ExternalIssuerSynced agree.
func ClearCertDrift(ctx context.Context, c client.Client, cert *cmapi.Certificate, reason, msg string) error {
	if err := clearSecretDrift(ctx, c, cert); err != nil {
		return err
	}
	original := cert.DeepCopy()
	SetExternalIssuerSynced(cert, true, reason, msg)
	return c.Status().Patch(ctx, cert, client.MergeFrom(original))
}
func MarkSecretDrift(ctx context.Context, c client.Client, cert *cmapi.Certificate, reason, msg string) error {
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{
		Name:      cert.Spec.SecretName,
		Namespace: cert.Namespace,
	}}
	if err := c.Get(ctx, client.ObjectKeyFromObject(secret), secret); err != nil {
		if apierrors.IsNotFound(err) {
			return nil
		}
		return fmt.Errorf("get secret %s/%s: %w", secret.Namespace, secret.Name, err)
	}
	if secret.Annotations[AnnotationExternalIssuerDriftReason] == reason &&
		secret.Annotations[AnnotationExternalIssuerDriftMessage] == msg {
		return nil
	}
	original := secret.DeepCopy()
	if secret.Annotations == nil {
		secret.Annotations = map[string]string{}
	}
	secret.Annotations[AnnotationExternalIssuerDriftReason] = reason
	secret.Annotations[AnnotationExternalIssuerDriftMessage] = msg
	secret.Annotations[AnnotationExternalIssuerDriftAt] = time.Now().UTC().Format(time.RFC3339)
	return c.Patch(ctx, secret, client.MergeFrom(original))
}

// ClearSecretDrift removes the three drift annotations after a successful
// sync. No-op when none are present, so we don't patch on every reconcile.
func clearSecretDrift(ctx context.Context, c client.Client, cert *cmapi.Certificate) error {
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{
		Name:      cert.Spec.SecretName,
		Namespace: cert.Namespace,
	}}
	if err := c.Get(ctx, client.ObjectKeyFromObject(secret), secret); err != nil {
		if apierrors.IsNotFound(err) {
			return nil
		}
		return fmt.Errorf("get secret %s/%s: %w", secret.Namespace, secret.Name, err)
	}
	if _, ok := secret.Annotations[AnnotationExternalIssuerDriftReason]; !ok {
		return nil
	}
	original := secret.DeepCopy()
	delete(secret.Annotations, AnnotationExternalIssuerDriftReason)
	delete(secret.Annotations, AnnotationExternalIssuerDriftMessage)
	delete(secret.Annotations, AnnotationExternalIssuerDriftAt)
	return c.Patch(ctx, secret, client.MergeFrom(original))
}

func secretPayloadEqual(a, b *corev1.Secret) bool {
	if a.Type != b.Type {
		return false
	}
	if !bytes.Equal(a.Data[corev1.TLSCertKey], b.Data[corev1.TLSCertKey]) {
		return false
	}
	if !bytes.Equal(a.Data[corev1.TLSPrivateKeyKey], b.Data[corev1.TLSPrivateKeyKey]) {
		return false
	}
	if ca, ok := a.Data[corev1.ServiceAccountRootCAKey]; ok {
		if !bytes.Equal(ca, b.Data[corev1.ServiceAccountRootCAKey]) {
			return false
		}
	} else if _, ok := b.Data[corev1.ServiceAccountRootCAKey]; ok {
		return false
	}
	for k, v := range b.Annotations {
		if a.Annotations[k] != v {
			return false
		}
	}
	return true
}
