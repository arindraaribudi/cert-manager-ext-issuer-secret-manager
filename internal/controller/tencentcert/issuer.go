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
	ctrlpkg "github.com/arindraaribudi/cert-manager-ext-issuer-secret-manager/internal/controller"
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
		ctrlpkg.SetReady(&cert, false, "IssuerNotFound", err.Error())
		_ = r.Status().Update(ctx, &cert)
		return ctrl.Result{}, err
	}
	creds, err := r.loadCredentials(ctx, spec, ns)
	if err != nil {
		ctrlpkg.SetReady(&cert, false, "MissingCredentials", err.Error())
		_ = r.Status().Update(ctx, &cert)
		return ctrl.Result{}, err
	}
	cli, err := r.NewSSLClient(creds, spec.Region, spec.Endpoint)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("tencentcert: new ssl client: %w", err)
	}

	parts, err := cli.Download(ctx, certID)
	if err != nil {
		ctrlpkg.SetReady(&cert, false, "DownloadFailed", err.Error())
		_ = r.Status().Update(ctx, &cert)
		return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
	}
	tlsCrt := tencentcert.AssembleTLS(parts.Leaf, parts.Chain)

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      cert.Spec.SecretName,
			Namespace: cert.Namespace,
		},
		Type: corev1.SecretTypeTLS,
		Data: map[string][]byte{
			corev1.TLSCertKey:       tlsCrt,
			corev1.TLSPrivateKeyKey: parts.PrivateKey,
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
	ctrlpkg.SetReady(&cert, true, "Synced", "certificate synced from Tencent SSL")
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

var _ = cmmeta.ConditionTrue
