package controller

import (
	"context"
	"errors"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	api "github.com/arindraaribudi/cert-manager-ext-issuer-secret-manager/api/v1alpha1"
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
	r.PayloadKeysFromIssuer = func(ctx context.Context, c *cmapi.Certificate) (api.PayloadKeys, error) {
		return api.PayloadKeys{}, nil
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
	// Use literal \n in the JSON string (escaped newlines), not raw newlines —
	// raw newlines inside a JSON string value are invalid syntax and fail
	// Extract with "invalid JSON". mustUnquote unescapes \n back to a real
	// newline on read, so compare against the unescaped form below.
	certPemEscaped := `-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----`
	keyPemEscaped := `-----BEGIN PRIVATE KEY-----\nMIIE\n-----END PRIVATE KEY-----`
	payload := []byte(`{"certificate":"` + certPemEscaped + `","private_key":"` + keyPemEscaped + `"}`)

	certPem := []byte("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----")
	keyPem := []byte("-----BEGIN PRIVATE KEY-----\nMIIE\n-----END PRIVATE KEY-----")

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
	r.PayloadKeysFromIssuer = func(ctx context.Context, c *cmapi.Certificate) (api.PayloadKeys, error) {
		return api.PayloadKeys{}, nil
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
