package controller

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	api "github.com/arindraaribudi/cert-manager-ext-issuer-secret-manager/api/v1alpha1"
	"github.com/arindraaribudi/cert-manager-ext-issuer-secret-manager/internal/keystore"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
)

// newTestReconciler wires a fake-client-backed IssuerReconciler with a
// minimal scheme. Status subresource is enabled for Certificate so
// Status().Update round-trips through the fake client.
func newTestReconciler(t *testing.T, objs ...client.Object) *IssuerReconciler {
	t.Helper()

	scheme := runtime.NewScheme()
	if err := cmapi.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	// ponytail: api/v1alpha1 AddToScheme panics here — SchemeBuilder.Register
	// in api/groupversion_info.go never sets GroupVersion, so AddKnownTypes
	// rejects empty GVKs. The reconciler test only needs cmapi + corev1, so
	// skip api registration. Fix the api package separately.

	cli := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(objs...).
		WithStatusSubresource(&cmapi.Certificate{}).
		Build()

	return &IssuerReconciler{Client: cli, Scheme: scheme}
}

// firstReason returns the Reason of the first condition on c, or "" if none.
func firstReason(c *cmapi.Certificate) string {
	if len(c.Status.Conditions) == 0 {
		return ""
	}
	return c.Status.Conditions[0].Reason
}

func TestReconcile_MissingAnnotation(t *testing.T) {
	cert := &cmapi.Certificate{
		ObjectMeta: metav1.ObjectMeta{Name: "c1", Namespace: "ns1"},
		Spec: cmapi.CertificateSpec{
			IssuerRef: cmmeta.ObjectReference{Name: "aws-iss", Kind: "AWSIssuer"},
		},
	}
	r := newTestReconciler(t, cert)

	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: "c1", Namespace: "ns1"}}); err != nil {
		t.Fatal(err)
	}

	var got cmapi.Certificate
	if err := r.Get(context.Background(), types.NamespacedName{Name: "c1", Namespace: "ns1"}, &got); err != nil {
		t.Fatal(err)
	}
	if firstReason(&got) != "MissingSecretRef" {
		t.Fatalf("reason = %q, want MissingSecretRef", firstReason(&got))
	}
	if got.Status.Conditions[0].Status != cmmeta.ConditionFalse {
		t.Fatalf("status = %v, want False", got.Status.Conditions[0].Status)
	}
}

func TestReconcile_UnknownKind(t *testing.T) {
	cert := &cmapi.Certificate{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "c1",
			Namespace: "ns1",
			Annotations: map[string]string{
				AnnotationSecretName: "cloud/secret",
			},
		},
		Spec: cmapi.CertificateSpec{
			IssuerRef: cmmeta.ObjectReference{Name: "nope", Kind: "UnknownKind"},
		},
	}
	r := newTestReconciler(t, cert)

	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: "c1", Namespace: "ns1"}}); err != nil {
		t.Fatal(err)
	}

	var got cmapi.Certificate
	if err := r.Get(context.Background(), types.NamespacedName{Name: "c1", Namespace: "ns1"}, &got); err != nil {
		t.Fatal(err)
	}
	if firstReason(&got) != "InvalidSpec" {
		t.Fatalf("reason = %q, want InvalidSpec", firstReason(&got))
	}
}

func TestReconcile_SourceMissing(t *testing.T) {
	cert := &cmapi.Certificate{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "c1",
			Namespace: "ns1",
			Annotations: map[string]string{
				AnnotationSecretName: "cloud/secret",
			},
		},
		Spec: cmapi.CertificateSpec{
			IssuerRef:  cmmeta.ObjectReference{Name: "aws-iss", Kind: "AWSIssuer"},
			SecretName: "tls-out",
		},
	}
	r := newTestReconciler(t, cert)
	r.ProviderResolvers = map[string]SecretResolver{
		"AWSIssuer": func(ctx context.Context, ref string) ([]byte, error) {
			return nil, errors.New("cloud unreachable")
		},
	}
	r.IssuerConfigFromIssuer = func(ctx context.Context, c *cmapi.Certificate) (api.IssuerConfig, error) {
		return api.IssuerConfig{}, nil
	}

	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: "c1", Namespace: "ns1"}}); err != nil {
		t.Fatal(err)
	}

	var got cmapi.Certificate
	if err := r.Get(context.Background(), types.NamespacedName{Name: "c1", Namespace: "ns1"}, &got); err != nil {
		t.Fatal(err)
	}
	if firstReason(&got) != "SourceMissing" {
		t.Fatalf("reason = %q, want SourceMissing", firstReason(&got))
	}
}

func TestReconcile_HappyPath(t *testing.T) {
	// Post-write verify (VerifySecretData) x509-parses tls.crt, so the
	// fixture must be a real certificate, not placeholder PEM bytes.
	certPem, keyPem := mustGenerateTestCertForController(t)
	certPemEscaped := strings.ReplaceAll(string(certPem), "\n", "\\n")
	keyPemEscaped := strings.ReplaceAll(string(keyPem), "\n", "\\n")
	payload := []byte(`{"certificate":"` + certPemEscaped + `","private_key":"` + keyPemEscaped + `"}`)

	cert := &cmapi.Certificate{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "c1",
			Namespace: "ns1",
			Annotations: map[string]string{
				AnnotationSecretName: "cloud/secret",
				AnnotationForceSync:  "true",
			},
		},
		Spec: cmapi.CertificateSpec{
			IssuerRef:  cmmeta.ObjectReference{Name: "aws-iss", Kind: "AWSIssuer"},
			SecretName: "tls-out",
		},
	}
	r := newTestReconciler(t, cert)
	r.ProviderResolvers = map[string]SecretResolver{
		"AWSIssuer": func(ctx context.Context, ref string) ([]byte, error) {
			if ref != "cloud/secret" {
				t.Fatalf("ref = %q, want cloud/secret", ref)
			}
			return payload, nil
		},
	}
	r.IssuerConfigFromIssuer = func(ctx context.Context, c *cmapi.Certificate) (api.IssuerConfig, error) {
		return api.IssuerConfig{}, nil
	}

	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: "c1", Namespace: "ns1"}}); err != nil {
		t.Fatalf("Reconcile error: %v", err)
	}

	// Secret must be created with cert + key bytes.
	var sec corev1.Secret
	if err := r.Get(context.Background(), types.NamespacedName{Name: "tls-out", Namespace: "ns1"}, &sec); err != nil {
		t.Fatal(err)
	}
	if string(sec.Data[corev1.TLSCertKey]) != string(certPem) {
		t.Errorf("tls.crt mismatch")
	}
	if string(sec.Data[corev1.TLSPrivateKeyKey]) != string(keyPem) {
		t.Errorf("tls.key mismatch")
	}
	if sec.Type != corev1.SecretTypeTLS {
		t.Errorf("type = %v, want TLS", sec.Type)
	}

	// All three issuer-* annotations must be present; missing any one
	// makes cert-manager report IncorrectIssuer on the next reconcile.
	if got := sec.Annotations["cert-manager.io/issuer-name"]; got != cert.Spec.IssuerRef.Name {
		t.Errorf("issuer-name annotation = %q, want %q", got, cert.Spec.IssuerRef.Name)
	}
	if got := sec.Annotations["cert-manager.io/issuer-kind"]; got != cert.Spec.IssuerRef.Kind {
		t.Errorf("issuer-kind annotation = %q, want %q", got, cert.Spec.IssuerRef.Kind)
	}
	if got := sec.Annotations["cert-manager.io/issuer-group"]; got != issuerGroup(cert.Spec.IssuerRef.Group) {
		t.Errorf("issuer-group annotation = %q, want %q", got, issuerGroup(cert.Spec.IssuerRef.Group))
	}

	// Certificate status: Ready=True, Synced.
	var got cmapi.Certificate
	if err := r.Get(context.Background(), types.NamespacedName{Name: "c1", Namespace: "ns1"}, &got); err != nil {
		t.Fatal(err)
	}
	if firstReason(&got) != "Synced" {
		t.Fatalf("reason = %q, want Synced", firstReason(&got))
	}
	if got.Status.Conditions[0].Status != cmmeta.ConditionTrue {
		t.Fatalf("status = %v, want True", got.Status.Conditions[0].Status)
	}

	// Force-sync annotation must be cleared.
	if _, ok := got.Annotations[AnnotationForceSync]; ok {
		t.Fatal("force-sync annotation not cleared")
	}
}

func TestReconcile_ClusterIssuerFanOut(t *testing.T) {
	certPem, keyPem := mustGenerateTestCertForController(t)
	certPemEscaped := strings.ReplaceAll(string(certPem), "\n", "\\n")
	keyPemEscaped := strings.ReplaceAll(string(keyPem), "\n", "\\n")
	payload := []byte(`{"certificate":"` + certPemEscaped + `","private_key":"` + keyPemEscaped + `"}`)

	cert := &cmapi.Certificate{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "c1",
			Namespace: "ns-cert",
			Annotations: map[string]string{
				AnnotationSecretName: "cloud/secret",
			},
		},
		Spec: cmapi.CertificateSpec{
			IssuerRef:  cmmeta.ObjectReference{Name: "aws-ci", Kind: "AWSSecretManagerClusterIssuer"},
			SecretName: "tls-out",
		},
	}
	nsCert := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "ns-cert"}}
	nsA := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "ns-a"}}
	nsB := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "ns-b"}}
	nsTerm := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: "ns-term"},
		Status:     corev1.NamespaceStatus{Phase: corev1.NamespaceTerminating},
	}

	r := newTestReconciler(t, cert, nsCert, nsA, nsB, nsTerm)
	r.ProviderResolvers = map[string]SecretResolver{
		"AWSSecretManagerClusterIssuer": func(ctx context.Context, ref string) ([]byte, error) {
			return payload, nil
		},
	}
	r.IssuerConfigFromIssuer = func(ctx context.Context, c *cmapi.Certificate) (api.IssuerConfig, error) {
		return api.IssuerConfig{}, nil
	}

	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: "c1", Namespace: "ns-cert"}}); err != nil {
		t.Fatalf("Reconcile error: %v", err)
	}

	// Secret must exist in ns-cert (cert's ns), ns-a, ns-b.
	for _, ns := range []string{"ns-cert", "ns-a", "ns-b"} {
		var sec corev1.Secret
		if err := r.Get(context.Background(), types.NamespacedName{Name: "tls-out", Namespace: ns}, &sec); err != nil {
			t.Fatalf("secret missing in %s: %v", ns, err)
		}
		if sec.Type != corev1.SecretTypeTLS {
			t.Errorf("%s: type = %v, want TLS", ns, sec.Type)
		}
	}

	// Cert's own namespace must carry the owner ref; others must not
	// (cross-namespace owner refs get silently garbage-collected by k8s).
	var secCert corev1.Secret
	if err := r.Get(context.Background(), types.NamespacedName{Name: "tls-out", Namespace: "ns-cert"}, &secCert); err != nil {
		t.Fatal(err)
	}
	if len(secCert.OwnerReferences) != 1 {
		t.Errorf("ns-cert: owner refs = %d, want 1", len(secCert.OwnerReferences))
	}
	var secA corev1.Secret
	if err := r.Get(context.Background(), types.NamespacedName{Name: "tls-out", Namespace: "ns-a"}, &secA); err != nil {
		t.Fatal(err)
	}
	if len(secA.OwnerReferences) != 0 {
		t.Errorf("ns-a: owner refs = %d, want 0", len(secA.OwnerReferences))
	}

	// Terminating ns must be skipped.
	var sec corev1.Secret
	err := r.Get(context.Background(), types.NamespacedName{Name: "tls-out", Namespace: "ns-term"}, &sec)
	if err == nil {
		t.Fatal("secret unexpectedly written to terminating namespace")
	}
}

func TestReconcile_ClusterIssuerFanOut_NamespaceFilter(t *testing.T) {
	certPem, keyPem := mustGenerateTestCertForController(t)
	certPemEscaped := strings.ReplaceAll(string(certPem), "\n", "\\n")
	keyPemEscaped := strings.ReplaceAll(string(keyPem), "\n", "\\n")
	payload := []byte(`{"certificate":"` + certPemEscaped + `","private_key":"` + keyPemEscaped + `"}`)

	cert := &cmapi.Certificate{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "c1",
			Namespace: "ns-cert",
			Annotations: map[string]string{
				AnnotationSecretName: "cloud/secret",
			},
		},
		Spec: cmapi.CertificateSpec{
			IssuerRef:  cmmeta.ObjectReference{Name: "aws-ci", Kind: "AWSSecretManagerClusterIssuer"},
			SecretName: "tls-out",
		},
	}
	nsCert := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "ns-cert"}}
	nsA := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "ns-a"}}
	nsB := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "ns-b"}}

	r := newTestReconciler(t, cert, nsCert, nsA, nsB)
	r.ProviderResolvers = map[string]SecretResolver{
		"AWSSecretManagerClusterIssuer": func(ctx context.Context, ref string) ([]byte, error) {
			return payload, nil
		},
	}
	r.IssuerConfigFromIssuer = func(ctx context.Context, c *cmapi.Certificate) (api.IssuerConfig, error) {
		return api.IssuerConfig{NamespaceFilter: api.NamespaceFilter{Allow: []string{"ns-a"}}}, nil
	}

	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: "c1", Namespace: "ns-cert"}}); err != nil {
		t.Fatalf("Reconcile error: %v", err)
	}

	// Allow-listed ns must get the secret; cert's own ns is not implicitly
	// added to an Allow list, so it's skipped here too.
	var sec corev1.Secret
	if err := r.Get(context.Background(), types.NamespacedName{Name: "tls-out", Namespace: "ns-a"}, &sec); err != nil {
		t.Fatalf("secret missing in ns-a: %v", err)
	}

	for _, ns := range []string{"ns-cert", "ns-b"} {
		var got corev1.Secret
		if err := r.Get(context.Background(), types.NamespacedName{Name: "tls-out", Namespace: ns}, &got); err == nil {
			t.Fatalf("secret unexpectedly written to %s (not in allow-list)", ns)
		}
	}
}

// TestReconcile_FanOutContinuesAfterOneNamespaceFails proves a write
// failure in one target namespace doesn't abort the rest of the fan-out —
// every other namespace must still get the fresh (post-drift) secret data
// in the same reconcile pass, not stale data until the next retry.
func TestReconcile_FanOutContinuesAfterOneNamespaceFails(t *testing.T) {
	certPem, keyPem := mustGenerateTestCertForController(t)
	certPemEscaped := strings.ReplaceAll(string(certPem), "\n", "\\n")
	keyPemEscaped := strings.ReplaceAll(string(keyPem), "\n", "\\n")
	payload := []byte(`{"certificate":"` + certPemEscaped + `","private_key":"` + keyPemEscaped + `"}`)

	cert := &cmapi.Certificate{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "c1",
			Namespace: "ns-cert",
			Annotations: map[string]string{
				AnnotationSecretName: "cloud/secret",
			},
		},
		Spec: cmapi.CertificateSpec{
			IssuerRef:  cmmeta.ObjectReference{Name: "aws-ci", Kind: "AWSSecretManagerClusterIssuer"},
			SecretName: "tls-out",
		},
	}
	nsCert := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "ns-cert"}}
	nsA := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "ns-a"}}
	nsB := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "ns-b"}}

	scheme := runtime.NewScheme()
	if err := cmapi.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	cli := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(cert, nsCert, nsA, nsB).
		WithStatusSubresource(&cmapi.Certificate{}).
		WithInterceptorFuncs(interceptor.Funcs{
			Create: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
				if s, ok := obj.(*corev1.Secret); ok && s.Namespace == "ns-a" {
					return errors.New("injected create failure for ns-a")
				}
				return c.Create(ctx, obj, opts...)
			},
		}).
		Build()
	r := &IssuerReconciler{Client: cli, Scheme: scheme}
	r.ProviderResolvers = map[string]SecretResolver{
		"AWSSecretManagerClusterIssuer": func(ctx context.Context, ref string) ([]byte, error) {
			return payload, nil
		},
	}
	r.IssuerConfigFromIssuer = func(ctx context.Context, c *cmapi.Certificate) (api.IssuerConfig, error) {
		return api.IssuerConfig{}, nil
	}

	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: "c1", Namespace: "ns-cert"}}); err != nil {
		t.Fatalf("Reconcile error: %v", err)
	}

	// ns-b must still get the secret even though ns-a's write failed —
	// the loop must not abort on the first error.
	var secB corev1.Secret
	if err := r.Get(context.Background(), types.NamespacedName{Name: "tls-out", Namespace: "ns-b"}, &secB); err != nil {
		t.Fatalf("ns-b secret missing (fan-out aborted early): %v", err)
	}
	var secCert corev1.Secret
	if err := r.Get(context.Background(), types.NamespacedName{Name: "tls-out", Namespace: "ns-cert"}, &secCert); err != nil {
		t.Fatalf("ns-cert secret missing (fan-out aborted early): %v", err)
	}

	// ns-a itself never got its secret, and the Certificate must report drift.
	var secA corev1.Secret
	if err := r.Get(context.Background(), types.NamespacedName{Name: "tls-out", Namespace: "ns-a"}, &secA); err == nil {
		t.Fatal("ns-a secret unexpectedly present despite injected write failure")
	}
	var got cmapi.Certificate
	if err := r.Get(context.Background(), types.NamespacedName{Name: "c1", Namespace: "ns-cert"}, &got); err != nil {
		t.Fatal(err)
	}
	if firstReason(&got) != "SecretWriteFailed" {
		t.Fatalf("reason = %q, want SecretWriteFailed", firstReason(&got))
	}
}

func TestReconcile_GeneratesKeystores(t *testing.T) {
	certPEM, keyPEM := mustGenerateTestCertForController(t)

	certPemEscaped := strings.ReplaceAll(string(certPEM), "\n", "\\n")
	keyPemEscaped := strings.ReplaceAll(string(keyPEM), "\n", "\\n")
	payload := []byte(`{"certificate":"` + certPemEscaped + `","private_key":"` + keyPemEscaped + `"}`)

	cert := &cmapi.Certificate{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "c1",
			Namespace: "ns1",
			Annotations: map[string]string{
				AnnotationSecretName: "cloud/secret",
			},
		},
		Spec: cmapi.CertificateSpec{
			IssuerRef:  cmmeta.ObjectReference{Name: "aws-iss", Kind: "AWSIssuer"},
			SecretName: "tls-out",
		},
	}
	r := newTestReconciler(t, cert)
	r.ProviderResolvers = map[string]SecretResolver{
		"AWSIssuer": func(ctx context.Context, ref string) ([]byte, error) {
			return payload, nil
		},
	}
	r.IssuerConfigFromIssuer = func(ctx context.Context, c *cmapi.Certificate) (api.IssuerConfig, error) {
		return api.IssuerConfig{}, nil
	}

	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: "c1", Namespace: "ns1"}}); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	var sec corev1.Secret
	if err := r.Get(context.Background(), types.NamespacedName{Name: "tls-out", Namespace: "ns1"}, &sec); err != nil {
		t.Fatal(err)
	}
	if len(sec.Data["keystore.jks"]) == 0 {
		t.Error("keystore.jks missing or empty")
	}
	if len(sec.Data["keystore.p12"]) == 0 {
		t.Error("keystore.p12 missing or empty")
	}
	if len(sec.Data["keystore.password"]) == 0 {
		t.Error("keystore.password missing or empty")
	}
	if err := keystore.ParseJKSForTest(sec.Data["keystore.jks"], sec.Data["keystore.password"]); err != nil {
		t.Errorf("JKS load failed: %v", err)
	}
}

// TestReconcile_EndToEnd_CompletesChainWithKnownRoot verifies the same gap
// found in CertSyncer also applied to IssuerReconciler: a source that ships
// leaf+intermediate but no root must still get the root appended to ca.crt,
// the chain annotation, and the keystore — not just tls.crt.
func TestReconcile_EndToEnd_CompletesChainWithKnownRoot(t *testing.T) {
	rootPEM, rootCert, rootKey := genCert(t, "sample-root-ca", true, nil, nil)
	intermediatePEM, interCert, interKey := genCert(t, "sample-intermediate", true, rootCert, rootKey)
	leafPEM, _, leafKey := genCert(t, "e2e-root.example.com", false, interCert, interKey)
	leafKeyDER, err := x509.MarshalPKCS8PrivateKey(leafKey)
	if err != nil {
		t.Fatal(err)
	}
	leafKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: leafKeyDER})

	origRoots := knownRoots
	knownRoots = [][]byte{rootPEM}
	defer func() { knownRoots = origRoots }()

	esc := func(b []byte) string { return strings.ReplaceAll(string(b), "\n", "\\n") }
	payload := []byte(`{"certificate":"` + esc(leafPEM) +
		`","private_key":"` + esc(leafKeyPEM) +
		`","certificate_chain":"` + esc(intermediatePEM) + `"}`)

	cert := &cmapi.Certificate{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "e2e-root-cert",
			Namespace: "ns1",
			Annotations: map[string]string{
				AnnotationSecretName: "cloud/secret-e2e-root",
			},
		},
		Spec: cmapi.CertificateSpec{
			IssuerRef:  cmmeta.ObjectReference{Name: "aws-iss", Kind: "AWSIssuer"},
			SecretName: "tls-e2e-root",
		},
	}
	r := newTestReconciler(t, cert)
	r.ProviderResolvers = map[string]SecretResolver{
		"AWSIssuer": func(ctx context.Context, ref string) ([]byte, error) {
			return payload, nil
		},
	}
	r.IssuerConfigFromIssuer = func(ctx context.Context, c *cmapi.Certificate) (api.IssuerConfig, error) {
		return api.IssuerConfig{}, nil
	}

	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: "e2e-root-cert", Namespace: "ns1"}}); err != nil {
		t.Fatalf("Reconcile error: %v", err)
	}

	var sec corev1.Secret
	if err := r.Get(context.Background(), types.NamespacedName{Name: "tls-e2e-root", Namespace: "ns1"}, &sec); err != nil {
		t.Fatal(err)
	}

	wantChain := NormalizePEM(append(append([]byte{}, intermediatePEM...), rootPEM...))
	if string(sec.Data[corev1.ServiceAccountRootCAKey]) != string(wantChain) {
		t.Errorf("ca.crt = %q, want intermediate+root %q", sec.Data[corev1.ServiceAccountRootCAKey], wantChain)
	}
	if got := sec.Annotations[AnnotationChain]; got != "leaf|intermediate|root" {
		t.Errorf("chain annotation = %q, want %q", got, "leaf|intermediate|root")
	}
	if len(sec.Data["keystore.jks"]) == 0 {
		t.Fatal("keystore.jks missing")
	}
	if err := keystore.ParseJKSForTest(sec.Data["keystore.jks"], sec.Data["keystore.password"]); err != nil {
		t.Fatalf("JKS load failed: %v", err)
	}
}

// TestReconcile_EndToEnd_SamplePEMProducesValidSecret feeds a realistic
// root-CA + leaf PEM chain through the full Reconcile path (chain
// validation, keystore build, post-write verify, cert-id annotation) and
// asserts every field of the produced Secret — this is the "sample PEM in,
// Secret out" check, not just an individual unit.
func TestReconcile_EndToEnd_SamplePEMProducesValidSecret(t *testing.T) {
	rootPEM, rootCert, rootKey := genCert(t, "sample-root-ca", true, nil, nil)
	leafPEM, _, leafKey := genCert(t, "e2e.example.com", false, rootCert, rootKey)
	leafKeyDER, err := x509.MarshalPKCS8PrivateKey(leafKey)
	if err != nil {
		t.Fatal(err)
	}
	leafKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: leafKeyDER})

	esc := func(b []byte) string { return strings.ReplaceAll(string(b), "\n", "\\n") }
	payload := []byte(`{"certificate":"` + esc(leafPEM) +
		`","private_key":"` + esc(leafKeyPEM) +
		`","certificate_chain":"` + esc(rootPEM) + `"}`)

	cert := &cmapi.Certificate{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "e2e-cert",
			Namespace: "ns1",
			Annotations: map[string]string{
				AnnotationSecretName: "cloud/secret-e2e",
			},
		},
		Spec: cmapi.CertificateSpec{
			IssuerRef:  cmmeta.ObjectReference{Name: "aws-iss", Kind: "AWSIssuer"},
			SecretName: "tls-e2e",
		},
	}
	r := newTestReconciler(t, cert)
	r.ProviderResolvers = map[string]SecretResolver{
		"AWSIssuer": func(ctx context.Context, ref string) ([]byte, error) {
			return payload, nil
		},
	}
	r.IssuerConfigFromIssuer = func(ctx context.Context, c *cmapi.Certificate) (api.IssuerConfig, error) {
		return api.IssuerConfig{}, nil
	}

	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: "e2e-cert", Namespace: "ns1"}}); err != nil {
		t.Fatalf("Reconcile error: %v", err)
	}

	var sec corev1.Secret
	if err := r.Get(context.Background(), types.NamespacedName{Name: "tls-e2e", Namespace: "ns1"}, &sec); err != nil {
		t.Fatal(err)
	}

	// TLS payload: leaf cert, leaf key, root chain.
	if string(sec.Data[corev1.TLSCertKey]) != string(NormalizePEM(leafPEM)) {
		t.Errorf("tls.crt mismatch")
	}
	if string(sec.Data[corev1.TLSPrivateKeyKey]) != string(NormalizePEM(leafKeyPEM)) {
		t.Errorf("tls.key mismatch")
	}
	if string(sec.Data[corev1.ServiceAccountRootCAKey]) != string(NormalizePEM(rootPEM)) {
		t.Errorf("ca.crt (chain) mismatch")
	}
	if sec.Type != corev1.SecretTypeTLS {
		t.Errorf("type = %v, want TLS", sec.Type)
	}

	// Keystores: present and load with the shipped password.
	if len(sec.Data["keystore.jks"]) == 0 || len(sec.Data["keystore.p12"]) == 0 || len(sec.Data["keystore.password"]) == 0 {
		t.Fatal("keystore.jks/p12/password missing")
	}
	if err := keystore.ParseJKSForTest(sec.Data["keystore.jks"], sec.Data["keystore.password"]); err != nil {
		t.Errorf("JKS load failed: %v", err)
	}

	// Annotations: leaf-derived metadata, issuer identity, cert-id, hashes.
	wantAnnotations := map[string]string{
		"cert-manager.io/common-name":  "e2e.example.com",
		"cert-manager.io/issuer-name":  "aws-iss",
		"cert-manager.io/issuer-kind":  "AWSIssuer",
		"cert-manager.io/issuer-group": "cert-manager.io",
		AnnotationSecretName:           "cloud/secret-e2e",
	}
	for k, want := range wantAnnotations {
		if got := sec.Annotations[k]; got != want {
			t.Errorf("annotation %s = %q, want %q", k, got, want)
		}
	}
	if sec.Annotations[AnnotationSourceHash] == "" {
		t.Error("source-hash annotation missing")
	}
	if sec.Annotations[AnnotationSecretHash] == "" {
		t.Error("secret-hash annotation missing")
	}

	// Certificate status: Ready=True, Synced — proves chain validation and
	// post-write verify both passed for this sample input.
	var gotCert cmapi.Certificate
	if err := r.Get(context.Background(), types.NamespacedName{Name: "e2e-cert", Namespace: "ns1"}, &gotCert); err != nil {
		t.Fatal(err)
	}
	if firstReason(&gotCert) != "Synced" || gotCert.Status.Conditions[0].Status != cmmeta.ConditionTrue {
		t.Fatalf("Certificate status = %+v, want Ready/Synced/True", gotCert.Status.Conditions)
	}
}

func mustGenerateTestCertForController(t *testing.T) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "controller-test.example.com"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:                  true,
		BasicConstraintsValid: true,
		DNSNames:              []string{"controller-test.example.com"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return
}
