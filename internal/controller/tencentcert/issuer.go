// Package tencentcertctrl mirrors Tencent SSL-issued certs into k8s TLS
// Secrets. Implements controller.CertSource; controller.CertSyncer owns
// the shared Reconcile skeleton (see internal/controller/certsync.go).
// Package name is tencentcertctrl (not tencentcert) to avoid collision
// with internal/tencentcert SDK helpers — Go would refuse the import otherwise.
package tencentcertctrl

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"

	tccommon "github.com/tencentcloud/tencentcloud-sdk-go-intl-en/tencentcloud/common"

	certapi "github.com/arindraaribudi/cert-manager-ext-issuer-secret-manager/api/certificates/v1alpha1"
	api "github.com/arindraaribudi/cert-manager-ext-issuer-secret-manager/api/v1alpha1"
	ctrlpkg "github.com/arindraaribudi/cert-manager-ext-issuer-secret-manager/internal/controller"
	"github.com/arindraaribudi/cert-manager-ext-issuer-secret-manager/internal/tencentcert"
)

const AnnotationCertID = "tencent.cert-manager.io/certificate-id"

// sslClientKey caches *tencentcert.SSLClient by (region, endpoint,
// credential-fingerprint). Unlike AWS, Tencent credentials genuinely vary
// per-Issuer (static Secret or ambient default chain), so the fingerprint
// is required to avoid sharing a client across Issuers with different
// static credentials — see credFingerprint.
type sslClientKey struct{ region, endpoint, credFingerprint string }

type IssuerReconciler struct {
	client.Client
	Scheme       *runtime.Scheme
	NewSSLClient func(creds tccommon.CredentialIface, region, endpoint string) (*tencentcert.SSLClient, error)
	clients      *ctrlpkg.ClientCache[sslClientKey, *tencentcert.SSLClient]
	clientsOnce  sync.Once
}

// credFingerprint returns a stable cache key for the resolved credentials:
// a hash of id+key for static credentials, or a fixed marker for the
// ambient chain (that provider is assumed to self-refresh internally —
// same as the AWS SDK's default chain, see acmClientKey in
// internal/controller/awscert/issuer.go for the analogous AWS-side note).
func credFingerprint(spec *certapi.TencentCertificateIssuerSpec, id, key string) string {
	if spec.SecretRef == nil || spec.SecretRef.Name == "" {
		return "ambient"
	}
	// Length-prefixed like HashSecretData in internal/controller/hash.go,
	// so id="a:b",key="c" and id="a",key="b:c" can't collide on the same
	// hash by concatenation ambiguity.
	h := sha256.New()
	_, _ = fmt.Fprintf(h, "%d:%s:%d:%s", len(id), id, len(key), key)
	return hex.EncodeToString(h.Sum(nil))
}

func (r *IssuerReconciler) Prefix() string        { return "tencentcert" }
func (r *IssuerReconciler) AnnotationKey() string { return AnnotationCertID }

// PostWrite deletes stale CertificateRequests cert-manager left behind
// (this controller bypasses the standard CR-signing flow; without this,
// cert-manager keeps re-issuing the CR on each reconcile and fights our
// Ready=True).
func (r *IssuerReconciler) PostWrite(ctx context.Context, cert *cmapi.Certificate) error {
	var crs cmapi.CertificateRequestList
	if err := r.List(ctx, &crs, client.InNamespace(cert.Namespace),
		client.MatchingLabels{"cert-manager.io/certificate-name": cert.Name}); err != nil {
		return fmt.Errorf("list stale CertificateRequests: %w", err)
	}
	for i := range crs.Items {
		if err := r.Delete(ctx, &crs.Items[i]); err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("delete CertificateRequest %s: %w", crs.Items[i].Name, err)
		}
	}
	return nil
}

// Reconcile delegates to the shared driver.
func (r *IssuerReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	syncer := &ctrlpkg.CertSyncer{Client: r.Client, Scheme: r.Scheme, Source: r}
	return syncer.Reconcile(ctx, req)
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

func (r *IssuerReconciler) loadCredentials(ctx context.Context, spec *certapi.TencentCertificateIssuerSpec, ns string) (tccommon.CredentialIface, string, error) {
	if spec.SecretRef != nil && spec.SecretRef.Name != "" {
		id, key, err := tencentcert.LoadStaticCredentials(ctx, r.Client, spec.SecretRef.Name, spec.SecretRef.GetNamespace(ns))
		if err != nil {
			return nil, "", err
		}
		return tccommon.NewCredential(id, key), credFingerprint(spec, id, key), nil
	}
	creds, err := tencentcert.BuildCredentialProvider(ctx)
	return creds, "ambient", err
}

// Fetch resolves the issuer, downloads the Tencent SSL cert, and
// chain-verifies the result.
func (r *IssuerReconciler) Fetch(ctx context.Context, cert *cmapi.Certificate, certID string) (*ctrlpkg.FetchResult, string, error) {
	spec, ns, err := r.resolveIssuer(ctx, cert)
	if err != nil {
		return nil, "IssuerNotFound", err
	}
	creds, fp, err := r.loadCredentials(ctx, spec, ns)
	if err != nil {
		return nil, "MissingCredentials", err
	}
	r.clientsOnce.Do(func() {
		r.clients = ctrlpkg.NewClientCache[sslClientKey, *tencentcert.SSLClient]()
	})
	key := sslClientKey{spec.Region, spec.Endpoint, fp}
	cli, err := r.clients.GetOrCreate(key, func() (*tencentcert.SSLClient, error) {
		return r.NewSSLClient(creds, spec.Region, spec.Endpoint)
	})
	if err != nil {
		return nil, "ClientBuildFailed", fmt.Errorf("tencentcert: new ssl client: %w", err)
	}

	parts, err := cli.Download(ctx, certID)
	if err != nil {
		return nil, "DownloadFailed", err
	}
	// A Tencent download ZIP carries the same leaf and key once per server
	// type (Nginx/, Apache/, IIS/, Tomcat/), and ExtractFromZIP concatenates
	// every matching file. Without this dedup tls.crt and tls.key ship four
	// copies of the same PEM block.
	parts.Leaf = ctrlpkg.NormalizePEM(parts.Leaf)
	parts.Chain = ctrlpkg.NormalizePEM(parts.Chain)
	parts.PrivateKey = ctrlpkg.NormalizePEM(parts.PrivateKey)

	if err := ctrlpkg.VerifyChain(parts.Leaf, parts.Chain); err != nil {
		return nil, "ChainInvalid", err
	}

	filter := api.NamespaceFilter{}
	if spec.NamespaceFilter != nil {
		filter = *spec.NamespaceFilter
	}
	interval := spec.ResyncInterval.Duration
	if interval <= 0 {
		interval = 12 * time.Hour
	}
	return &ctrlpkg.FetchResult{
		LeafPEM:         parts.Leaf,
		ChainPEM:        parts.Chain,
		KeyPEM:          parts.PrivateKey,
		NamespaceFilter: filter,
		ResyncInterval:  interval,
	}, "", nil
}
