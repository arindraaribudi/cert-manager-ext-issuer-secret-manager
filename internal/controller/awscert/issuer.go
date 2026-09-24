// Package awscertctrl mirrors ACM-issued certs into k8s TLS Secrets.
// Implements controller.CertSource; controller.CertSyncer owns the shared
// Reconcile skeleton (see internal/controller/certsync.go).
// Package name is awscertctrl (not awscert) to avoid collision with
// internal/awscert SDK helpers — Go would refuse the import otherwise.
package awscertctrl

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/acm"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"

	certapi "github.com/arindraaribudi/cert-manager-ext-issuer-secret-manager/api/certificates/v1alpha1"
	api "github.com/arindraaribudi/cert-manager-ext-issuer-secret-manager/api/v1alpha1"
	"github.com/arindraaribudi/cert-manager-ext-issuer-secret-manager/internal/awscert"
	controller "github.com/arindraaribudi/cert-manager-ext-issuer-secret-manager/internal/controller"
	"github.com/arindraaribudi/cert-manager-ext-issuer-secret-manager/internal/keystore"
)

// AnnotationARN is the cert-id annotation on Certificate CRs.
const AnnotationARN = "acm.cert-manager.io/certificate-arn"

// acmClientKey caches *acm.Client by (region, endpoint) only. This is safe
// today because real ACM auth always comes from the ambient SDK credential
// chain built inside NewACM — internal/awscert.LoadStaticCredentials (which
// would read spec.SecretRef's access-key-id/secret-access-key) is not wired
// into any production path. If that changes, this key must also include a
// credential fingerprint (e.g. a hash of the resolved static keys), or two
// Issuers sharing region+endpoint but different static credentials will
// silently share one client.
type acmClientKey struct{ region, endpoint string }

// IssuerReconciler fetches an ACM cert and mirrors it into a k8s Secret.
// NewACM is a factory: tests inject a stub; production wires *acm.Client.
type IssuerReconciler struct {
	client.Client
	Scheme      *runtime.Scheme
	NewACM      func(ctx context.Context, region, endpoint string) (*acm.Client, error)
	clients     *controller.ClientCache[acmClientKey, *acm.Client]
	clientsOnce sync.Once
}

func (r *IssuerReconciler) Prefix() string        { return "awscert" }
func (r *IssuerReconciler) AnnotationKey() string { return AnnotationARN }

func (r *IssuerReconciler) PostWrite(ctx context.Context, cert *cmapi.Certificate) error {
	return nil
}

// Reconcile delegates to the shared driver.
func (r *IssuerReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	syncer := &controller.CertSyncer{Client: r.Client, Scheme: r.Scheme, Source: r}
	return syncer.Reconcile(ctx, req)
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
// endpoint). Returns "" passphrase if absent — caller decides whether
// absence is fatal.
func (r *IssuerReconciler) loadCredentials(ctx context.Context, spec *certapi.AWSCertificateIssuerSpec, ns string) (string, error) {
	if spec.SecretRef != nil && spec.SecretRef.Name != "" {
		pp, _ := awscert.LoadPassphrase(ctx, r.Client, spec.SecretRef, ns)
		return pp, nil
	}
	return "", nil
}

// Fetch resolves the issuer, downloads the ACM cert, decrypts the private
// key if present, and chain-verifies the result.
func (r *IssuerReconciler) Fetch(ctx context.Context, cert *cmapi.Certificate, arn string) (*controller.FetchResult, string, error) {
	spec, ns, err := r.resolveIssuer(ctx, cert)
	if err != nil {
		return nil, "IssuerNotFound", err
	}
	passphrase, err := r.loadCredentials(ctx, spec, ns)
	if err != nil {
		return nil, "MissingCredentials", err
	}
	r.clientsOnce.Do(func() {
		r.clients = controller.NewClientCache[acmClientKey, *acm.Client]()
	})
	acmClient, err := r.clients.GetOrCreate(acmClientKey{spec.Region, spec.Endpoint}, func() (*acm.Client, error) {
		return r.NewACM(ctx, spec.Region, spec.Endpoint)
	})
	if err != nil {
		return nil, "ClientBuildFailed", fmt.Errorf("awscert: new client: %w", err)
	}
	cl := awscert.New(acmClient)

	raw, err := cl.Export(ctx, arn, passphrase)
	if err != nil {
		return nil, "DownloadFailed", err
	}
	chain, encKey, err := awscert.SplitPEM(raw)
	if err != nil {
		return nil, "DownloadFailed", err
	}
	// ACM can repeat the leaf inside the returned chain; without this the
	// duplicate blocks accumulate in tls.crt on every sync.
	chain = controller.NormalizePEM(chain)
	var key []byte
	if len(encKey) > 0 {
		key, err = awscert.DecryptPKCS8(encKey, passphrase)
		if err != nil {
			return nil, "DecryptFailed", err
		}
	}

	leafPEM, chainOnly := keystore.SplitLeafAndChain(chain)
	if err := controller.VerifyChain(leafPEM, chainOnly); err != nil {
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
	return &controller.FetchResult{
		LeafPEM:         leafPEM,
		ChainPEM:        chainOnly,
		KeyPEM:          key,
		NamespaceFilter: filter,
		ResyncInterval:  interval,
	}, "", nil
}
