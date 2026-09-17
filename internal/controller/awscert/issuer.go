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
	"github.com/arindraaribudi/cert-manager-ext-issuer-secret-manager/internal/awscert"
	controller "github.com/arindraaribudi/cert-manager-ext-issuer-secret-manager/internal/controller"
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
		controller.SetReady(&cert, false, "IssuerNotFound", err.Error())
		_ = r.Status().Update(ctx, &cert)
		return ctrl.Result{}, err
	}

	passphrase, err := r.loadCredentials(ctx, spec, ns)
	if err != nil {
		controller.SetReady(&cert, false, "MissingCredentials", err.Error())
		_ = r.Status().Update(ctx, &cert)
		return ctrl.Result{}, err
	}
	acmClient, err := r.NewACM(ctx, spec.Region, spec.Endpoint)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("awscert: new client: %w", err)
	}
	cl := awscert.New(acmClient)

	raw, err := cl.Export(ctx, arn, passphrase)
	if err != nil {
		controller.SetReady(&cert, false, "DownloadFailed", err.Error())
		_ = r.Status().Update(ctx, &cert)
		return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
	}

	chain, encKey, err := awscert.SplitPEM(raw)
	if err != nil {
		controller.SetReady(&cert, false, "DownloadFailed", err.Error())
		_ = r.Status().Update(ctx, &cert)
		return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
	}
	var key []byte
	if len(encKey) > 0 {
		key, err = awscert.DecryptPKCS8(encKey, passphrase)
		if err != nil {
			controller.SetReady(&cert, false, "DecryptFailed", err.Error())
			_ = r.Status().Update(ctx, &cert)
			return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
		}
	}

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      cert.Spec.SecretName,
			Namespace: cert.Namespace,
		},
		Type: corev1.SecretTypeTLS,
		Data: map[string][]byte{
			corev1.TLSCertKey:       chain,
			corev1.TLSPrivateKeyKey: key,
		},
	}
	if err := controllerutil.SetControllerReference(&cert, secret, r.Scheme); err != nil {
		// Fall back to non-blocking owner ref — works for cluster-scoped issuers.
		secret.OwnerReferences = []metav1.OwnerReference{{
			APIVersion:         "cert-manager.io/v1",
			Kind:               "Certificate",
			Name:               cert.Name,
			UID:                cert.UID,
			Controller:         ptr(true),
			BlockOwnerDeletion: ptr(true),
		}}
	}
	if err := upsertSecret(ctx, r.Client, secret); err != nil {
		return ctrl.Result{}, err
	}

	controller.SetReady(&cert, true, "Synced", "certificate synced from ACM")
	if err := r.Status().Update(ctx, &cert); err != nil {
		return ctrl.Result{}, err
	}
	interval := spec.ResyncInterval.Duration
	if interval <= 0 {
		interval = 12 * time.Hour
	}
	return ctrl.Result{RequeueAfter: interval}, nil
}

func upsertSecret(ctx context.Context, c client.Client, desired *corev1.Secret) error {
	existing := &corev1.Secret{}
	err := c.Get(ctx, client.ObjectKeyFromObject(desired), existing)
	if apierrors.IsNotFound(err) {
		return c.Create(ctx, desired)
	}
	if err != nil {
		return err
	}
	existing.Data = desired.Data
	existing.Type = desired.Type
	return c.Update(ctx, existing)
}