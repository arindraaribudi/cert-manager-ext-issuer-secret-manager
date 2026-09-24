package controller

import (
	"context"
	"errors"
	"testing"
	"time"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	api "github.com/arindraaribudi/cert-manager-ext-issuer-secret-manager/api/v1alpha1"
)

// testLeafPEM is a real (but throwaway) self-signed cert — VerifySecretData
// runs x509.ParseCertificate on whatever CertSyncer writes, so the fixture
// must be valid DER, not just PEM-shaped placeholder text.
const testLeafPEM = `-----BEGIN CERTIFICATE-----
MIIBIzCBy6ADAgECAgEBMAoGCCqGSM49BAMCMBIxEDAOBgNVBAoTB0FjbWUgQ28w
HhcNMjQwMTAxMDAwMDAwWhcNMzQwMTAxMDAwMDAwWjASMRAwDgYDVQQKEwdBY21l
IENvMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE61nMDF8r401jdPglYqNShZT5
WD1EmbXsVnt8Qy1wAbwKRS0HCwy1AiEcM3He7LTxvL9je5Yu7eSxjO7IetwaXaMS
MBAwDgYDVR0PAQH/BAQDAgeAMAoGCCqGSM49BAMCA0cAMEQCIH1bxySyud6yh+8t
n+MtYFhiyljsYep3/dDqwqhHCxXjAiAB7yRwPGdgpsojKm2v9E3Ra31m+ZAfslLS
x34bdfW8kQ==
-----END CERTIFICATE-----
`

func newTestScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	if err := cmapi.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	return s
}

// stubSource is a CertSource whose behavior is set per test.
type stubSource struct {
	annotationKey  string
	fetchResult    *FetchResult
	fetchReason    string
	fetchErr       error
	postWriteErr   error
	postWriteCalls int
	fetchCalls     int
}

func (s *stubSource) Prefix() string        { return "stub" }
func (s *stubSource) AnnotationKey() string { return s.annotationKey }
func (s *stubSource) Fetch(ctx context.Context, cert *cmapi.Certificate, ref string) (*FetchResult, string, error) {
	s.fetchCalls++
	return s.fetchResult, s.fetchReason, s.fetchErr
}
func (s *stubSource) PostWrite(ctx context.Context, cert *cmapi.Certificate) error {
	s.postWriteCalls++
	return s.postWriteErr
}

func newTestCert(name, ns, annKey, annVal string) *cmapi.Certificate {
	return &cmapi.Certificate{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns, Annotations: map[string]string{annKey: annVal}},
		Spec: cmapi.CertificateSpec{
			SecretName: name + "-tls",
			IssuerRef:  cmmeta.ObjectReference{Name: "iss", Kind: "K", Group: "certificates.cert-manager.io"},
		},
	}
}

func TestCertSyncer_Reconcile_NoAnnotation_NoOp(t *testing.T) {
	s := newTestScheme(t)
	cert := newTestCert("c1", "default", "other-key", "")
	cert.Annotations = map[string]string{} // no gate annotation at all
	kube := fake.NewClientBuilder().WithScheme(s).WithObjects(cert).WithStatusSubresource(&cmapi.Certificate{}).Build()
	src := &stubSource{annotationKey: "gate-key"}
	r := &CertSyncer{Client: kube, Scheme: s, Source: src}

	res, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: "c1", Namespace: "default"}})
	if err != nil || res.Requeue || res.RequeueAfter != 0 {
		t.Fatalf("want no-op result, got res=%+v err=%v", res, err)
	}
}

func TestCertSyncer_Reconcile_FetchError_MarksDriftAndRequeues(t *testing.T) {
	s := newTestScheme(t)
	cert := newTestCert("c2", "default", "gate-key", "ref-1")
	kube := fake.NewClientBuilder().WithScheme(s).WithObjects(cert).WithStatusSubresource(&cmapi.Certificate{}).Build()
	src := &stubSource{annotationKey: "gate-key", fetchReason: "DownloadFailed", fetchErr: errors.New("boom")}
	r := &CertSyncer{Client: kube, Scheme: s, Source: src}

	res, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: "c2", Namespace: "default"}})
	if err != nil {
		t.Fatalf("want nil error (RequeueAfterError swallows it), got %v", err)
	}
	if res.RequeueAfter != 30*time.Second {
		t.Fatalf("want 30s requeue, got %v", res.RequeueAfter)
	}

	var got cmapi.Certificate
	if err := kube.Get(context.Background(), types.NamespacedName{Name: "c2", Namespace: "default"}, &got); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, c := range got.Status.Conditions {
		if c.Type == ConditionTypeExternalIssuerSynced && c.Reason == "DownloadFailed" {
			found = true
		}
	}
	if !found {
		t.Fatalf("want ExternalIssuerSynced/DownloadFailed condition, got %+v", got.Status.Conditions)
	}
}

func TestCertSyncer_Reconcile_Success_WritesSecretAndSetsResyncInterval(t *testing.T) {
	s := newTestScheme(t)
	cert := newTestCert("c3", "default", "gate-key", "ref-1")
	kube := fake.NewClientBuilder().WithScheme(s).WithObjects(cert).WithStatusSubresource(&cmapi.Certificate{}).Build()
	_, keyPEM := mustGenerateTestCertForController(t)
	src := &stubSource{
		annotationKey: "gate-key",
		fetchResult: &FetchResult{
			LeafPEM:         []byte(testLeafPEM),
			ChainPEM:        nil,
			KeyPEM:          keyPEM,
			NamespaceFilter: api.NamespaceFilter{},
			ResyncInterval:  5 * time.Minute,
		},
	}
	r := &CertSyncer{Client: kube, Scheme: s, Source: src}

	res, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: "c3", Namespace: "default"}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.RequeueAfter != 5*time.Minute {
		t.Fatalf("want 5m resync interval, got %v", res.RequeueAfter)
	}
	if src.postWriteCalls != 1 {
		t.Fatalf("want PostWrite called once, got %d", src.postWriteCalls)
	}

	var sec corev1.Secret
	if err := kube.Get(context.Background(), types.NamespacedName{Name: "c3-tls", Namespace: "default"}, &sec); err != nil {
		t.Fatalf("expected Secret to be written: %v", err)
	}
	if sec.Annotations["gate-key"] != "ref-1" {
		t.Fatalf("want gate annotation stamped on Secret, got %q", sec.Annotations["gate-key"])
	}
}

func TestCertSyncer_Reconcile_AddsFinalizer(t *testing.T) {
	s := newTestScheme(t)
	cert := newTestCert("c4", "default", "gate-key", "ref-1")
	kube := fake.NewClientBuilder().WithScheme(s).WithObjects(cert).WithStatusSubresource(&cmapi.Certificate{}).Build()
	// fetchErr short-circuits after the finalizer is added, so this test
	// stays isolated from the write/verify path exercised elsewhere.
	src := &stubSource{annotationKey: "gate-key", fetchReason: "DownloadFailed", fetchErr: errors.New("boom")}
	r := &CertSyncer{Client: kube, Scheme: s, Source: src}

	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: "c4", Namespace: "default"}}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var got cmapi.Certificate
	if err := kube.Get(context.Background(), types.NamespacedName{Name: "c4", Namespace: "default"}, &got); err != nil {
		t.Fatal(err)
	}
	if !controllerutil.ContainsFinalizer(&got, FinalizerName) {
		t.Fatalf("want finalizer %q added, got %v", FinalizerName, got.Finalizers)
	}
}

func TestCertSyncer_Reconcile_Deleting_RemovesFinalizer_NoFetch(t *testing.T) {
	s := newTestScheme(t)
	cert := newTestCert("c5", "default", "gate-key", "ref-1")
	cert.Finalizers = []string{FinalizerName}
	kube := fake.NewClientBuilder().WithScheme(s).WithObjects(cert).WithStatusSubresource(&cmapi.Certificate{}).Build()
	// Deleting an object with a finalizer present sets DeletionTimestamp
	// but keeps the object around until the finalizer is removed.
	if err := kube.Delete(context.Background(), cert); err != nil {
		t.Fatalf("delete: %v", err)
	}

	src := &stubSource{annotationKey: "gate-key"}
	r := &CertSyncer{Client: kube, Scheme: s, Source: src}

	res, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: "c5", Namespace: "default"}})
	if err != nil || res.Requeue || res.RequeueAfter != 0 {
		t.Fatalf("want no-op result, got res=%+v err=%v", res, err)
	}
	if src.fetchCalls != 0 {
		t.Fatalf("want Fetch not called during deletion, got %d calls", src.fetchCalls)
	}

	var got cmapi.Certificate
	err = kube.Get(context.Background(), types.NamespacedName{Name: "c5", Namespace: "default"}, &got)
	if err == nil {
		if len(got.Finalizers) != 0 {
			t.Fatalf("want finalizer removed, got %v", got.Finalizers)
		}
	} else if !apierrors.IsNotFound(err) {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCertSyncer_Reconcile_KeystoreSkipped_NoPrivateKey(t *testing.T) {
	s := newTestScheme(t)
	cert := newTestCert("c6", "default", "gate-key", "ref-1")
	kube := fake.NewClientBuilder().WithScheme(s).WithObjects(cert).WithStatusSubresource(&cmapi.Certificate{}).Build()
	src := &stubSource{
		annotationKey: "gate-key",
		fetchResult: &FetchResult{
			LeafPEM: []byte(testLeafPEM),
			// KeyPEM nil -> BuildKeystore/keystore.Build reports skipped=true
			// (JKS/PKCS12 need a private key; TLS half still ships).
			KeyPEM:          nil,
			NamespaceFilter: api.NamespaceFilter{},
			ResyncInterval:  5 * time.Minute,
		},
	}
	r := &CertSyncer{Client: kube, Scheme: s, Source: src}

	res, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: "c6", Namespace: "default"}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Keystore-skip is not fatal: Reconcile still reaches the success path
	// and requeues at the source's resync interval, not the 30s error path.
	if res.RequeueAfter != 5*time.Minute {
		t.Fatalf("want success-path 5m resync, got %v", res.RequeueAfter)
	}

	var sec corev1.Secret
	if err := kube.Get(context.Background(), types.NamespacedName{Name: "c6-tls", Namespace: "default"}, &sec); err != nil {
		t.Fatalf("expected Secret to be written: %v", err)
	}
	for _, k := range []string{"keystore.jks", "keystore.p12", "keystore.password"} {
		if _, ok := sec.Data[k]; ok {
			t.Fatalf("want %s absent from written Secret (no private key), got present", k)
		}
	}

	// NOTE: the driver marks ExternalIssuerSynced=False/KeystoreSkipped
	// mid-reconcile, but on this happy path (write+verify both succeed) the
	// unconditional ClearCertDrift call at the end of Reconcile overwrites
	// it back to True/Synced before returning — so the skip is transient
	// and not observable in the final condition. Verified empirically; the
	// final condition really is Synced, not KeystoreSkipped.
	var got cmapi.Certificate
	if err := kube.Get(context.Background(), types.NamespacedName{Name: "c6", Namespace: "default"}, &got); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, c := range got.Status.Conditions {
		if c.Type == ConditionTypeExternalIssuerSynced && c.Reason == "Synced" {
			found = true
		}
	}
	if !found {
		t.Fatalf("want ExternalIssuerSynced/Synced condition (keystore-skip is transient), got %+v", got.Status.Conditions)
	}
}
