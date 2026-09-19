// Package awscertctrl mirrors ACM-issued certs into k8s TLS Secrets.
// ponytail: drop-in shape matching reference repo's IssuerReconciler;
// custom because SecretResolver API has no slot for the private key.
// Package name is awscertctrl (not awscert) to avoid collision with
// internal/awscert SDK helpers — Go would refuse the import otherwise.
package awscertctrl

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/acm"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"

	certapi "github.com/arindraaribudi/cert-manager-ext-issuer-secret-manager/api/certificates/v1alpha1"
	api "github.com/arindraaribudi/cert-manager-ext-issuer-secret-manager/api/v1alpha1"
	"github.com/arindraaribudi/cert-manager-ext-issuer-secret-manager/internal/awscert"
	controller "github.com/arindraaribudi/cert-manager-ext-issuer-secret-manager/internal/controller"
	"github.com/arindraaribudi/cert-manager-ext-issuer-secret-manager/internal/keystore"
)

// AnnotationARN is the cert-id annotation on Certificate CRs.
const AnnotationARN = "acm.cert-manager.io/certificate-arn"

const finalizerName = "certificates.cert-manager.io/finalizer"

// IssuerReconciler fetches an ACM cert and mirrors it into a k8s Secret.
// NewACM is a factory: tests inject a stub; production wires *acm.Client.
type IssuerReconciler struct {
	client.Client
	Scheme *runtime.Scheme
	NewACM func(ctx context.Context, region, endpoint string) (*acm.Client, error)
}

func ptr[T any](v T) *T { return &v }

// setReady updates the Ready condition via a merge patch on the status
// subresource. Patches don't bump the main resourceVersion, so cert-manager's
// trigger-loop Update on the same Certificate won't race with us on
// optimistic locking — same fix as tencentcert/setReady. Kills the per-minute
// Ready False→True churn in cert-manager core.
func (r *IssuerReconciler) setReady(ctx context.Context, cert *cmapi.Certificate, ok bool, reason, msg string) error {
	original := cert.DeepCopy()
	controller.SetReady(cert, ok, reason, msg)
	return r.Status().Patch(ctx, cert, client.MergeFrom(original))
}

// hasARNAnnotation reports whether the Certificate carries our annotation.
func hasARNAnnotation(obj client.Object) bool {
	_, ok := obj.GetAnnotations()[AnnotationARN]
	return ok
}

// ARNFromCertificate returns the annotation value, or "" + false if absent.
func ARNFromCertificate(c *cmapi.Certificate) (string, bool) {
	v, ok := c.GetAnnotations()[AnnotationARN]
	return v, ok && v != ""
}

// resolveIssuer returns the Spec for the Issuer kind referenced by cert.
func (r *IssuerReconciler) resolveIssuer(ctx context.Context, cert *cmapi.Certificate) (*certapi.AWSCertificateIssuerSpec, string, error) {
	ref := cert.Spec.IssuerRef
	if ref.Group != "certificates.cert-manager.io" {
		return nil, "", fmt.Errorf("awscert: unexpected issuer group %q", ref.Group)
	}
	switch ref.Kind {
	case "AWSCertificateClusterIssuer":
		var iss certapi.AWSCertificateClusterIssuer
		if err := r.Get(ctx, types.NamespacedName{Name: ref.Name}, &iss); err != nil {
			return nil, "", fmt.Errorf("get AWSCertificateClusterIssuer: %w", err)
		}
		return &iss.Spec, iss.Spec.SecretRef.GetNamespace(cert.Namespace), nil
	case "AWSCertificateIssuer":
		var iss certapi.AWSCertificateIssuer
		if err := r.Get(ctx, types.NamespacedName{Name: ref.Name, Namespace: cert.Namespace}, &iss); err != nil {
			return nil, "", fmt.Errorf("get AWSCertificateIssuer: %w", err)
		}
		return &iss.Spec, iss.Spec.SecretRef.GetNamespace(cert.Namespace), nil
	default:
		return nil, "", fmt.Errorf("awscert: unexpected issuer kind %q", ref.Kind)
	}
}

// loadCredentials resolves the AWS passphrase. Static-credential config and
// IRSA default-chain are both built inside NewACM (factory injects region +
// endpoint). ponytail: keeps the reconciler agnostic to which auth path runs.
// Returns "" passphrase if absent — caller decides whether absence is fatal.
func (r *IssuerReconciler) loadCredentials(ctx context.Context, spec *certapi.AWSCertificateIssuerSpec, ns string) (string, error) {
	if spec.SecretRef != nil && spec.SecretRef.Name != "" {
		pp, _ := awscert.LoadPassphrase(ctx, r.Client, spec.SecretRef, ns)
		return pp, nil
	}
	return "", nil
}

func (r *IssuerReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var cert cmapi.Certificate
	if err := r.Get(ctx, req.NamespacedName, &cert); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	arn, ok := ARNFromCertificate(&cert)
	if !ok {
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
		_ = controller.MarkCertDrift(ctx, r.Client, &cert, "IssuerNotFound", err.Error())
		return controller.RequeueAfterError(ctx, err, "awscert: resolve issuer",
			"cert", req.String(), "issuerRef", fmt.Sprintf("%s/%s/%s", cert.Spec.IssuerRef.Group, cert.Spec.IssuerRef.Kind, cert.Spec.IssuerRef.Name)), nil
	}

	passphrase, err := r.loadCredentials(ctx, spec, ns)
	if err != nil {
		_ = controller.MarkCertDrift(ctx, r.Client, &cert, "MissingCredentials", err.Error())
		return controller.RequeueAfterError(ctx, err, "awscert: load credentials",
			"cert", req.String()), nil
	}
	acmClient, err := r.NewACM(ctx, spec.Region, spec.Endpoint)
	if err != nil {
		_ = controller.MarkCertDrift(ctx, r.Client, &cert, "ClientBuildFailed", err.Error())
		return controller.RequeueAfterError(ctx, fmt.Errorf("awscert: new client: %w", err), "awscert: build ACM client",
			"cert", req.String(), "region", spec.Region), nil
	}
	cl := awscert.New(acmClient)

	raw, err := cl.Export(ctx, arn, passphrase)
	if err != nil {
		_ = controller.MarkCertDrift(ctx, r.Client, &cert, "DownloadFailed", err.Error())
		return controller.RequeueAfterError(ctx, err, "awscert: export certificate",
			"cert", req.String(), "arn", arn, "region", spec.Region), nil
	}

	chain, encKey, err := awscert.SplitPEM(raw)
	if err != nil {
		_ = controller.MarkCertDrift(ctx, r.Client, &cert, "DownloadFailed", err.Error())
		return controller.RequeueAfterError(ctx, err, "awscert: split PEM",
			"cert", req.String(), "arn", arn), nil
	}
	var key []byte
	if len(encKey) > 0 {
		key, err = awscert.DecryptPKCS8(encKey, passphrase)
		if err != nil {
			_ = controller.MarkCertDrift(ctx, r.Client, &cert, "DecryptFailed", err.Error())
			return controller.RequeueAfterError(ctx, err, "awscert: decrypt private key",
				"cert", req.String(), "arn", arn), nil
		}
	}

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:        cert.Spec.SecretName,
			Namespace:   cert.Namespace,
			Annotations: map[string]string{},
		},
		Type: corev1.SecretTypeTLS,
		Data: map[string][]byte{
			corev1.TLSCertKey:       chain,
			corev1.TLSPrivateKeyKey: key,
		},
	}
	// ponytail: stamp cert-manager.io/issuer-{name,kind,group} on every
	// Secret — without these cert-manager reports IncorrectIssuer on the
	// synced Secret and refuses to trust it. Same trick the GCP controller
	// uses.
	secret.Annotations["cert-manager.io/issuer-name"] = cert.Spec.IssuerRef.Name
	secret.Annotations["cert-manager.io/issuer-kind"] = cert.Spec.IssuerRef.Kind
	secret.Annotations["cert-manager.io/issuer-group"] = cert.Spec.IssuerRef.Group
	for k, v := range controller.CertAnnotations(chain) {
		secret.Annotations[k] = v
	}

	// Fan-out: ClusterIssuer → every non-terminating ns (filtered). Issuer
	// → cert.Namespace. Owner ref only on the cert.Namespace copy —
	// cross-ns owner refs are silently dropped by k8s and the GC deletes
	// the dependent right after Create.
	filter := api.NamespaceFilter{}
	if spec.NamespaceFilter != nil {
		filter = *spec.NamespaceFilter
	}

	// Build keystore auxiliary keys. Read existing cert-ns Secret for
	// password stability across reconciles. awscert has no separate
	// chain variable: chain (from SplitPEM) is leaf+chain in one PEM
	// bundle, so pass it as certPEM and nil as chainPEM — the keystore
	// builder only reads the first block as the leaf.
	keystoreExisting := &corev1.Secret{}
	keystoreExistingNS := cert.Namespace
	keystoreGetErr := r.Get(ctx, types.NamespacedName{Name: cert.Spec.SecretName, Namespace: keystoreExistingNS}, keystoreExisting)
	if apierrors.IsNotFound(keystoreGetErr) {
		keystoreExisting = nil
	} else if keystoreGetErr != nil {
		_ = controller.MarkCertDrift(ctx, r.Client, &cert, "SecretReadFailed", keystoreGetErr.Error())
		return controller.RequeueAfterError(ctx, keystoreGetErr, "awscert: read existing secret for keystore build",
			"cert", req.String()), nil
	}

	leafPEM, chainOnly := keystore.SplitLeafAndChain(chain)
	jks, p12, pw, skipped, err := keystore.Build(leafPEM, key, chainOnly, keystoreExisting)
	if err != nil {
		_ = controller.MarkCertDrift(ctx, r.Client, &cert, "KeystoreBuildFailed", err.Error())
		// fall through — TLS half still ships; keystore drift visible on next reconcile.
	} else if skipped {
		_ = controller.MarkCertDrift(ctx, r.Client, &cert, "KeystoreSkipped", "ACM export lacks private key; JKS/PKCS12 not generated")
	} else {
		secret.Data["keystore.jks"] = jks
		secret.Data["keystore.p12"] = p12
		secret.Data["keystore.password"] = pw
	}

	targets, err := controller.TargetNamespaces(ctx, r.Client, &cert, filter)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("list namespaces: %w", err)
	}
	for _, ns := range targets {
		desired := secret.DeepCopy()
		desired.Namespace = ns
		if ns == cert.Namespace {
			if err := controllerutil.SetControllerReference(&cert, desired, r.Scheme); err != nil {
				// Fall back to non-blocking owner ref — works for cluster-scoped issuers.
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
		if err := controller.WriteSecret(ctx, r.Client, desired); err != nil {
			return ctrl.Result{}, err
		}
	}

	_ = controller.ClearCertDrift(ctx, r.Client, &cert, "Synced", "certificate synced from ACM")
	if err := r.setReady(ctx, &cert, true, "Synced", "certificate synced from ACM"); err != nil {
		return ctrl.Result{}, err
	}
	interval := spec.ResyncInterval.Duration
	if interval <= 0 {
		interval = 12 * time.Hour
	}
	return ctrl.Result{RequeueAfter: interval}, nil
}