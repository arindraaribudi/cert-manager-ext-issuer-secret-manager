// Package casource — tests. Fake Reconciler with an in-memory Fetch
// closure, asserting the shared skeleton writes a clean Opaque Secret
// with only data["ca.crt"] (no stray tls.crt/tls.key, the half-broken
// state of the pre-revert e831dc8 chain-only path).
package casource

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	api "github.com/arindraaribudi/cert-manager-ext-issuer-secret-manager/api/v1alpha1"
	"github.com/arindraaribudi/cert-manager-ext-issuer-secret-manager/internal/controller"
)

const samplePEM = "-----BEGIN CERTIFICATE-----\nMIIBfake...\n-----END CERTIFICATE-----\n"

func TestReconcile_WritesOpaqueSecretWithChainOnly(t *testing.T) {
	payload, _ := json.Marshal(map[string]string{"certificate_chain": samplePEM})
	fetch := func(_ context.Context, _ FetchSpec) ([]byte, error) { return payload, nil }

	r := &Reconciler{
		Client: fake.NewClientBuilder().Build(),
		Prefix: "test",
		Fetch:  fetch,
	}
	in := ReconcileInput{
		Region:         "us-east-1",
		SecretName:     "my-ca-bundle",
		TargetNS:       "cert-manager",
		TargetName:     "aws-roots",
		ResyncInterval: time.Hour,
	}
	result, status, err := r.Reconcile(context.Background(), in, nil)
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if result.RequeueAfter != time.Hour {
		t.Errorf("RequeueAfter = %v, want %v", result.RequeueAfter, time.Hour)
	}
	if status == nil {
		t.Fatal("status is nil")
	}
	if status.SourceHash == "" {
		t.Error("SourceHash empty")
	}
	if status.LastSyncTime == "" {
		t.Error("LastSyncTime empty")
	}
	if len(status.Conditions) != 1 || status.Conditions[0].Type != conditionReady {
		t.Errorf("expected one Ready=True condition, got %#v", status.Conditions)
	}

	got := &corev1.Secret{}
	if err := r.Get(context.Background(), types.NamespacedName{Namespace: "cert-manager", Name: "aws-roots"}, got); err != nil {
		t.Fatalf("Get target Secret: %v", err)
	}
	if got.Type != corev1.SecretTypeOpaque {
		t.Errorf("Secret.Type = %v, want Opaque", got.Type)
	}
	if string(got.Data["ca.crt"]) != samplePEM {
		t.Errorf("Secret.Data[ca.crt] = %q, want %q", got.Data["ca.crt"], samplePEM)
	}
	if _, ok := got.Data["tls.crt"]; ok {
		t.Error("Secret.Data has tls.crt (should not — CASource writes Opaque, not TLS)")
	}
	if _, ok := got.Data["tls.key"]; ok {
		t.Error("Secret.Data has tls.key (should not — CASource writes Opaque, not TLS)")
	}
	if got.Annotations[controller.AnnotationSourceHash] == "" {
		t.Error("Secret.Annotations missing source-hash")
	}
	if got.Annotations[controller.AnnotationLastSyncTime] == "" {
		t.Error("Secret.Annotations missing last-sync-time")
	}
}

func TestReconcile_DefaultsTargetNS(t *testing.T) {
	fetch := func(_ context.Context, _ FetchSpec) ([]byte, error) {
		return []byte(`{"certificate_chain": "PEM"}`), nil
	}
	r := &Reconciler{
		Client: fake.NewClientBuilder().Build(),
		Prefix: "test",
		Fetch:  fetch,
	}
	in := ReconcileInput{SecretName: "x", TargetName: "y"}
	if _, _, err := r.Reconcile(context.Background(), in, nil); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	got := &corev1.Secret{}
	if err := r.Get(context.Background(), types.NamespacedName{Namespace: defaultTargetNS, Name: "y"}, got); err != nil {
		t.Fatalf("expected Secret in default target ns %q: %v", defaultTargetNS, err)
	}
}

func TestReconcile_DefaultsResyncInterval(t *testing.T) {
	fetch := func(_ context.Context, _ FetchSpec) ([]byte, error) {
		return []byte(`{"certificate_chain": "PEM"}`), nil
	}
	r := &Reconciler{Client: fake.NewClientBuilder().Build(), Prefix: "test", Fetch: fetch}
	result, _, err := r.Reconcile(context.Background(), ReconcileInput{TargetName: "y"}, nil)
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if result.RequeueAfter != defaultResyncInterval {
		t.Errorf("RequeueAfter = %v, want default %v", result.RequeueAfter, defaultResyncInterval)
	}
}

func TestReconcile_MissingChainField(t *testing.T) {
	fetch := func(_ context.Context, _ FetchSpec) ([]byte, error) {
		return []byte(`{"certificate": "PEM"}`), nil // wrong key
	}
	r := &Reconciler{Client: fake.NewClientBuilder().Build(), Prefix: "test", Fetch: fetch}
	_, _, err := r.Reconcile(context.Background(), ReconcileInput{TargetName: "y"}, nil)
	if err == nil {
		t.Fatal("expected error on missing certificate_chain field")
	}
	if !strings.Contains(err.Error(), "certificate_chain") {
		t.Errorf("error should name missing field, got: %v", err)
	}
}

func TestReconcile_FetchError(t *testing.T) {
	fetch := func(_ context.Context, _ FetchSpec) ([]byte, error) {
		return nil, errFake
	}
	r := &Reconciler{Client: fake.NewClientBuilder().Build(), Prefix: "test", Fetch: fetch}
	_, _, err := r.Reconcile(context.Background(), ReconcileInput{TargetName: "y"}, nil)
	if err == nil {
		t.Fatal("expected error from fetch failure")
	}
}

func TestExtractChain(t *testing.T) {
	tests := []struct {
		name    string
		payload string
		want    string
		wantErr bool
	}{
		{"happy", `{"certificate_chain": "PEM"}`, "PEM", false},
		{"missing field", `{"certificate": "PEM"}`, "", true},
		{"empty string", `{"certificate_chain": ""}`, "", true},
		{"quoted empty", `{"certificate_chain": ""}`, "", true},
		{"invalid json", `not json`, "", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := extractChain([]byte(tc.payload))
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr = %v", err, tc.wantErr)
			}
			if !tc.wantErr && string(got) != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

var errFake = errFakeErr("fetch failed")

type errFakeErr string

func (e errFakeErr) Error() string { return string(e) }

// silence unused-import vet for metav1 + api + ctrl used in fixtures
var (
	_ = metav1.Now
	_ = ctrl.Request{}
	_ = (*api.AWSSecretManagerCASource)(nil)
)
