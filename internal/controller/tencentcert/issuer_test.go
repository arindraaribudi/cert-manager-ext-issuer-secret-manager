package tencentcertctrl

import (
	"context"
	"errors"
	"testing"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	tccommon "github.com/tencentcloud/tencentcloud-sdk-go-intl-en/tencentcloud/common"
	sslapi "github.com/tencentcloud/tencentcloud-sdk-go-intl-en/tencentcloud/ssl/v20191205"

	certapi "github.com/arindraaribudi/cert-manager-ext-issuer-secret-manager/api/certificates/v1alpha1"
	"github.com/arindraaribudi/cert-manager-ext-issuer-secret-manager/internal/tencentcert"
)

// fakeSSLAPI satisfies tencentcert's unexported sslAPI interface
// structurally (Go interface satisfaction doesn't require naming it) so
// Download returns a clean error instead of panicking on a nil interface.
type fakeSSLAPI struct{}

func (fakeSSLAPI) DownloadCertificateWithContext(_ context.Context, _ *sslapi.DownloadCertificateRequest) (*sslapi.DownloadCertificateResponse, error) {
	return nil, errors.New("fakeSSLAPI: not implemented")
}

func TestReconcile_CreatesSecret(t *testing.T) {
	t.Skip("requires KUBEBUILDER_ASSETS envtest binary; see controller/setup_envtest_test.go")
}

func TestReconcile_AnnotationFilter(t *testing.T) {
	t.Skip("requires KUBEBUILDER_ASSETS envtest binary; see controller/setup_envtest_test.go")
	ctrl.SetLogger(zap.New(zap.UseDevMode(true)))
	testScheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(testScheme)
	_ = cmapi.AddToScheme(testScheme)
	_ = certapi.AddToScheme(testScheme)
	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:  testScheme,
		Metrics: metricsserver.Options{BindAddress: "0"},
	})
	if err != nil {
		t.Fatal(err)
	}
	r := &IssuerReconciler{
		Client: mgr.GetClient(),
		NewSSLClient: func(_ tccommon.CredentialIface, _, _ string) (*tencentcert.SSLClient, error) {
			return nil, nil
		},
	}
	if err := r.SetupWithManager(mgr); err != nil {
		t.Fatal(err)
	}
	_ = cmmeta.ConditionTrue
	_ = cmapi.Certificate{}
}

// TestFetch_CachesSSLClientByCredentialFingerprint proves NewSSLClient is
// only invoked once for repeated Reconciles against the same
// (region, endpoint, credential) combination. Mirrors
// awscertctrl.TestFetch_CachesACMClientByRegionEndpoint — Reconcile()
// doesn't need a running envtest manager (CertSyncer only touches
// r.Client), so this runs against a fake client instead of skipping.
func TestFetch_CachesSSLClientByCredentialFingerprint(t *testing.T) {
	testScheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(testScheme)
	_ = cmapi.AddToScheme(testScheme)
	_ = certapi.AddToScheme(testScheme)

	credSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "tencent-creds", Namespace: "default"},
		Data: map[string][]byte{
			"secret-id":  []byte("AKID-test"),
			"secret-key": []byte("secret-test"),
		},
	}
	issuer := &certapi.TencentCertificateIssuer{
		ObjectMeta: metav1.ObjectMeta{Name: "iss1", Namespace: "default"},
		Spec: certapi.TencentCertificateIssuerSpec{
			Region:    "ap-singapore",
			SecretRef: &certapi.TencentSecretRef{Name: "tencent-creds"},
		},
	}
	cert := &cmapi.Certificate{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "c1",
			Namespace: "default",
			Annotations: map[string]string{
				AnnotationCertID: "abcdefgh",
			},
		},
		Spec: cmapi.CertificateSpec{
			SecretName: "c1-tls",
			IssuerRef:  cmmeta.ObjectReference{Name: "iss1", Kind: "TencentCertificateIssuer", Group: "certificates.cert-manager.io"},
		},
	}
	kube := fake.NewClientBuilder().WithScheme(testScheme).WithObjects(cert, issuer, credSecret).WithStatusSubresource(&cmapi.Certificate{}).Build()

	calls := 0
	r := &IssuerReconciler{
		Client: kube,
		Scheme: testScheme,
		NewSSLClient: func(_ tccommon.CredentialIface, _, _ string) (*tencentcert.SSLClient, error) {
			calls++
			return tencentcert.New(fakeSSLAPI{}), nil
		},
	}

	req := ctrl.Request{NamespacedName: types.NamespacedName{Name: cert.Name, Namespace: cert.Namespace}}

	_, _ = r.Reconcile(context.Background(), req)
	_, _ = r.Reconcile(context.Background(), req)
	if calls != 1 {
		t.Fatalf("NewSSLClient called %d times across 2 reconciles with unchanged credentials, want 1", calls)
	}
}

// TestFetch_CachesSSLClientByCredentialFingerprint_BustsOnRotation proves
// the cache key's credential-fingerprint dimension is actually load-bearing:
// rotating the static Secret's id/key (same region/endpoint, same
// reconciler/cache instance) must produce a cache miss, not a silent reuse
// of the client built under the old credentials.
func TestFetch_CachesSSLClientByCredentialFingerprint_BustsOnRotation(t *testing.T) {
	testScheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(testScheme)
	_ = cmapi.AddToScheme(testScheme)
	_ = certapi.AddToScheme(testScheme)

	credSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "tencent-creds", Namespace: "default"},
		Data: map[string][]byte{
			"secret-id":  []byte("id-a"),
			"secret-key": []byte("key-a"),
		},
	}
	issuer := &certapi.TencentCertificateIssuer{
		ObjectMeta: metav1.ObjectMeta{Name: "iss1", Namespace: "default"},
		Spec: certapi.TencentCertificateIssuerSpec{
			Region:    "ap-singapore",
			SecretRef: &certapi.TencentSecretRef{Name: "tencent-creds"},
		},
	}
	cert := &cmapi.Certificate{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "c1",
			Namespace: "default",
			Annotations: map[string]string{
				AnnotationCertID: "abcdefgh",
			},
		},
		Spec: cmapi.CertificateSpec{
			SecretName: "c1-tls",
			IssuerRef:  cmmeta.ObjectReference{Name: "iss1", Kind: "TencentCertificateIssuer", Group: "certificates.cert-manager.io"},
		},
	}
	kube := fake.NewClientBuilder().WithScheme(testScheme).WithObjects(cert, issuer, credSecret).WithStatusSubresource(&cmapi.Certificate{}).Build()

	calls := 0
	r := &IssuerReconciler{
		Client: kube,
		Scheme: testScheme,
		NewSSLClient: func(_ tccommon.CredentialIface, _, _ string) (*tencentcert.SSLClient, error) {
			calls++
			return tencentcert.New(fakeSSLAPI{}), nil
		},
	}

	req := ctrl.Request{NamespacedName: types.NamespacedName{Name: cert.Name, Namespace: cert.Namespace}}

	_, _ = r.Reconcile(context.Background(), req)
	if calls != 1 {
		t.Fatalf("NewSSLClient called %d times after first reconcile, want 1", calls)
	}

	// Rotate the credential Secret in place — same reconciler/cache
	// instance, same region/endpoint, only id/key change.
	var live corev1.Secret
	if err := kube.Get(context.Background(), types.NamespacedName{Name: "tencent-creds", Namespace: "default"}, &live); err != nil {
		t.Fatalf("get credential secret: %v", err)
	}
	live.Data["secret-id"] = []byte("id-b")
	live.Data["secret-key"] = []byte("key-b")
	if err := kube.Update(context.Background(), &live); err != nil {
		t.Fatalf("update credential secret: %v", err)
	}

	_, _ = r.Reconcile(context.Background(), req)
	if calls != 2 {
		t.Fatalf("NewSSLClient called %d times after credential rotation, want 2 (cache should miss on new fingerprint)", calls)
	}
}
