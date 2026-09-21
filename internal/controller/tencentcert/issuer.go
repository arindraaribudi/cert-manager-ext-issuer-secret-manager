// Package tencentcertctrl mirrors Tencent SSL-issued certs into k8s TLS Secrets.
// ponytail: same drop-in shape as awscertctrl controller; differs only in
// SDK (Tencent SSL vs ACM) and credential keys (secret-id/secret-key vs
// access-key-id/secret-access-key).
//
// Package name is tencentcertctrl (not tencentcert) to avoid collision
// with internal/tencentcert SDK helpers — Go would refuse the import otherwise.
package tencentcertctrl

import (
	"context"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"

	tccommon "github.com/tencentcloud/tencentcloud-sdk-go-intl-en/tencentcloud/common"

	certapi "github.com/arindraaribudi/cert-manager-ext-issuer-secret-manager/api/certificates/v1alpha1"
	api "github.com/arindraaribudi/cert-manager-ext-issuer-secret-manager/api/v1alpha1"
	ctrlpkg "github.com/arindraaribudi/cert-manager-ext-issuer-secret-manager/internal/controller"
	"github.com/arindraaribudi/cert-manager-ext-issuer-secret-manager/internal/keystore"
	"github.com/arindraaribudi/cert-manager-ext-issuer-secret-manager/internal/tencentcert"
)

const AnnotationCertID = "tencent.cert-manager.io/certificate-id"
const finalizerName = "certificates.cert-manager.io/finalizer"

type IssuerReconciler struct {
	client.Client
	Scheme       *runtime.Scheme
	NewSSLClient func(creds tccommon.CredentialIface, region, endpoint string) (*tencentcert.SSLClient, error)
}

func ptr[T any](v T) *T { return &v }

// setReady updates the Ready condition via a merge patch on the status
// subresource. Patches don't bump the main resourceVersion, so cert-manager's
// trigger-loop Update on the same object won't see a stale rv and re-queue
// with "object has been modified" — the optimistic-locking ping-pong we hit
// before. ponytail: this is the standard cert-manager-aware fix for shared
// controllers.
func (r *IssuerReconciler) setReady(ctx context.Context, cert *cmapi.Certificate, status bool, reason, msg string) error {
	original := cert.DeepCopy()
	ctrlpkg.SetReady(cert, status, reason, msg)
	return r.Status().Patch(ctx, cert, client.MergeFrom(original))
}

func hasCertIDAnnotation(obj client.Object) bool {
	_, ok := obj.GetAnnotations()[AnnotationCertID]
	return ok
}

func (r *IssuerReconciler) resolveIssuer(ctx context.Context, cert *cmapi.Certificate) (*certapi.TencentCertificateIssuerSpec, string, error) {
	ref := cert.Spec.IssuerRef
	if ref.Group != "certificates.cert-manager.io" {
		return nil, "", fmt.Errorf("tencentcert: unexpected issuer group %q", ref.Group)
	}
	switch ref.Kind {
	case "TencentCertificateClusterIssuer":
		var iss certapi.TencentCertificateClusterIssuer
		if err := r.Get(ctx, types.NamespacedName{Name: ref.Name}, &iss); err != nil {
			return nil, "", fmt.Errorf("get TencentCertificateClusterIssuer: %w", err)
		}
		return &iss.Spec, iss.Spec.SecretRef.GetNamespace(cert.Namespace), nil
	case "TencentCertificateIssuer":
		var iss certapi.TencentCertificateIssuer
		if err := r.Get(ctx, types.NamespacedName{Name: ref.Name, Namespace: cert.Namespace}, &iss); err != nil {
			return nil, "", fmt.Errorf("get TencentCertificateIssuer: %w", err)
		}
		return &iss.Spec, iss.Spec.SecretRef.GetNamespace(cert.Namespace), nil
	default:
		return nil, "", fmt.Errorf("tencentcert: unexpected issuer kind %q", ref.Kind)
	}
}

func (r *IssuerReconciler) loadCredentials(ctx context.Context, spec *certapi.TencentCertificateIssuerSpec, ns string) (tccommon.CredentialIface, error) {
	if spec.SecretRef != nil && spec.SecretRef.Name != "" {
		id, key, err := tencentcert.LoadStaticCredentials(ctx, r.Client, spec.SecretRef.Name, spec.SecretRef.GetNamespace(ns))
		if err != nil {
			return nil, err
		}
		return tccommon.NewCredential(id, key), nil
	}
	return tencentcert.BuildCredentialProvider(ctx)
}

func (r *IssuerReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var cert cmapi.Certificate
	if err := r.Get(ctx, req.NamespacedName, &cert); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	certID, hasID := cert.GetAnnotations()[AnnotationCertID]
	if !hasID || certID == "" {
		return ctrl.Result{}, nil
	}
	if !cert.DeletionTimestamp.IsZero() {
		if controllerutil.ContainsFinalizer(&cert, finalizerName) {
			controllerutil.RemoveFinalizer(&cert, finalizerName)
			if err := r.Update(ctx, &cert); err != nil {
				return ctrl.Result{}, err
			}
		}
		return ctrl.Result{}, nil
	}
	if !controllerutil.ContainsFinalizer(&cert, finalizerName) {
		controllerutil.AddFinalizer(&cert, finalizerName)
		if err := r.Update(ctx, &cert); err != nil {
			return ctrl.Result{}, err
		}
	}

	spec, ns, err := r.resolveIssuer(ctx, &cert)
	if err != nil {
		_ = ctrlpkg.MarkCertDrift(ctx, r.Client, &cert, "IssuerNotFound", err.Error())
		return ctrlpkg.RequeueAfterError(ctx, err, "tencentcert: resolve issuer",
			"cert", req.String(), "issuerRef", fmt.Sprintf("%s/%s/%s", cert.Spec.IssuerRef.Group, cert.Spec.IssuerRef.Kind, cert.Spec.IssuerRef.Name)), nil
	}
	creds, err := r.loadCredentials(ctx, spec, ns)
	if err != nil {
		_ = ctrlpkg.MarkCertDrift(ctx, r.Client, &cert, "MissingCredentials", err.Error())
		return ctrlpkg.RequeueAfterError(ctx, err, "tencentcert: load credentials",
			"cert", req.String(), "secretRef", fmt.Sprintf("%s/%s", ns, spec.SecretRef.Name)), nil
	}
	cli, err := r.NewSSLClient(creds, spec.Region, spec.Endpoint)
	if err != nil {
		_ = ctrlpkg.MarkCertDrift(ctx, r.Client, &cert, "ClientBuildFailed", err.Error())
		return ctrlpkg.RequeueAfterError(ctx, fmt.Errorf("tencentcert: new ssl client: %w", err), "tencentcert: build SSL client",
			"cert", req.String(), "region", spec.Region), nil
	}

	parts, err := cli.Download(ctx, certID)
	if err != nil {
		_ = ctrlpkg.MarkCertDrift(ctx, r.Client, &cert, "DownloadFailed", err.Error())
		return ctrlpkg.RequeueAfterError(ctx, err, "tencentcert: download certificate",
			"cert", req.String(), "certID", certID, "region", spec.Region), nil
	}
	tlsCrt := tencentcert.AssembleTLS(parts.Leaf, parts.Chain)

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      cert.Spec.SecretName,
			Namespace: cert.Namespace,
			Annotations: map[string]string{
				"cert-manager.io/issuer-name":  cert.Spec.IssuerRef.Name,
				"cert-manager.io/issuer-kind":  cert.Spec.IssuerRef.Kind,
				"cert-manager.io/issuer-group": cert.Spec.IssuerRef.Group,
			},
		},
		Type: corev1.SecretTypeTLS,
		Data: map[string][]byte{
			corev1.TLSCertKey:       tlsCrt,
			corev1.TLSPrivateKeyKey: parts.PrivateKey,
		},
	}
	// ponytail: stamp leaf-cert info annotations (common-name, alt-names,
	// not-before, not-after) so the Secret matches what cert-manager itself
	// would write on Secrets it owns. nil on parse failure — informational.
	for k, v := range ctrlpkg.CertAnnotations(parts.Leaf) {
		secret.Annotations[k] = v
	}

	// Fan-out: ClusterIssuer → every non-terminating ns (filtered). Issuer
	// → cert.Namespace. Owner ref only on the cert.Namespace copy —
	// cross-ns owner refs are silently dropped by k8s.
	filter := api.NamespaceFilter{}
	if spec.NamespaceFilter != nil {
		filter = *spec.NamespaceFilter
	}

	// Build keystore auxiliary keys. Read existing cert-ns Secret for
	// password stability across reconciles. tencentcert separates leaf
	// and chain, so pass both — builder reads first PEM block as leaf
	// and appends chain to JKS/PKCS12 trust chain.
	keystoreExisting := &corev1.Secret{}
	keystoreExistingNS := cert.Namespace
	keystoreGetErr := r.Get(ctx, types.NamespacedName{Name: cert.Spec.SecretName, Namespace: keystoreExistingNS}, keystoreExisting)
	if apierrors.IsNotFound(keystoreGetErr) {
		keystoreExisting = nil
	} else if keystoreGetErr != nil {
		_ = ctrlpkg.MarkCertDrift(ctx, r.Client, &cert, "SecretReadFailed", keystoreGetErr.Error())
		return ctrlpkg.RequeueAfterError(ctx, keystoreGetErr, "tencentcert: read existing secret for keystore build",
			"cert", req.String()), nil
	}

	jks, p12, pw, skipped, err := keystore.Build(parts.Leaf, parts.PrivateKey, parts.Chain, keystoreExisting)
	if err != nil {
		_ = ctrlpkg.MarkCertDrift(ctx, r.Client, &cert, "KeystoreBuildFailed", err.Error())
		// fall through — TLS half still ships; keystore drift visible on next reconcile.
	} else if skipped {
		_ = ctrlpkg.MarkCertDrift(ctx, r.Client, &cert, "KeystoreSkipped", "Tencent SSL lacks private key; JKS/PKCS12 not generated")
	} else {
		secret.Data["keystore.jks"] = jks
		secret.Data["keystore.p12"] = p12
		secret.Data["keystore.password"] = pw
	}

	targets, err := ctrlpkg.TargetNamespaces(ctx, r.Client, &cert, filter)
	if err != nil {
		return ctrlpkg.RequeueAfterError(ctx, fmt.Errorf("list namespaces: %w", err), "tencentcert: list target namespaces"), nil
	}
	for _, ns := range targets {
		desired := secret.DeepCopy()
		desired.Namespace = ns
		if ns == cert.Namespace {
			if err := controllerutil.SetControllerReference(&cert, desired, r.Scheme); err != nil {
				desired.OwnerReferences = []metav1.OwnerReference{{
					APIVersion:         "cert-manager.io/v1",
					Kind:               "Certificate",
					Name:               cert.Name,
					UID:                cert.UID,
					Controller:         ptr(true),
					BlockOwnerDeletion: ptr(true),
				}}
			}
		}
		if err := ctrlpkg.WriteSecret(ctx, r.Client, desired); err != nil {
			return ctrlpkg.RequeueAfterError(ctx, err, "tencentcert: write secret", "namespace", ns), nil
		}
	}
	if err := deleteStaleRequests(ctx, r.Client, req.Namespace, cert.Name); err != nil {
		return ctrlpkg.RequeueAfterError(ctx, err, "tencentcert: delete stale CertificateRequests"), nil
	}
	_ = ctrlpkg.ClearCertDrift(ctx, r.Client, &cert, "Synced", "certificate synced from Tencent SSL")
	if err := r.setReady(ctx, &cert, true, "Synced", "certificate synced from Tencent SSL"); err != nil {
		return ctrlpkg.RequeueAfterError(ctx, err, "tencentcert: setReady true"), nil
	}
	interval := spec.ResyncInterval.Duration
	if interval <= 0 {
		interval = 12 * time.Hour
	}
	return ctrl.Result{RequeueAfter: interval}, nil
}

// deleteStaleRequests removes CertificateRequests left behind by cert-manager
// when this controller bypasses the standard CR-signing flow. Without this,
// cert-manager keeps re-issuing the CR on each reconcile and fights our
// Ready=True.
func deleteStaleRequests(ctx context.Context, c client.Client, namespace, certName string) error {
	var crs cmapi.CertificateRequestList
	if err := c.List(ctx, &crs, client.InNamespace(namespace),
		client.MatchingLabels{"cert-manager.io/certificate-name": certName}); err != nil {
		return fmt.Errorf("list stale CertificateRequests: %w", err)
	}
	for i := range crs.Items {
		if err := c.Delete(ctx, &crs.Items[i]); err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("delete CertificateRequest %s: %w", crs.Items[i].Name, err)
		}
	}
	return nil
}

var _ = cmmeta.ConditionTrue
