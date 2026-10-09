package tencent

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestIsTkePodIdentity_AllEnv(t *testing.T) {
	t.Setenv("TKE_REGION", "ap-bangkok")
	t.Setenv("TKE_PROVIDER_ID", "pid")
	t.Setenv("TKE_WEB_IDENTITY_TOKEN_FILE", "/token")
	t.Setenv("TKE_ROLE_ARN", "qcs::cam::uin/123:role/r")
	if !IsTkePodIdentity() {
		t.Fatal("want true when all 4 envs set")
	}
}

func TestIsTkePodIdentity_Partial(t *testing.T) {
	// Missing one → false. Run with no env to start, then set one at a time.
	for _, k := range []string{"TKE_REGION", "TKE_PROVIDER_ID", "TKE_WEB_IDENTITY_TOKEN_FILE", "TKE_ROLE_ARN"} {
		t.Setenv(k, "x")
	}
	// Now all 4 are set → true; unset each one in turn and re-check.
	for _, missing := range []string{"TKE_REGION", "TKE_PROVIDER_ID", "TKE_WEB_IDENTITY_TOKEN_FILE", "TKE_ROLE_ARN"} {
		t.Setenv(missing, "")
		if IsTkePodIdentity() {
			t.Fatalf("want false when %s empty", missing)
		}
		t.Setenv(missing, "x")
	}
}

func TestResolveCredential_FallbackToStatic(t *testing.T) {
	// Ensure no TKE env leaks in from the test runner.
	for _, k := range []string{"TKE_REGION", "TKE_PROVIDER_ID", "TKE_WEB_IDENTITY_TOKEN_FILE", "TKE_ROLE_ARN"} {
		t.Setenv(k, "")
	}
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	creds := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "tc-creds", Namespace: "cert-manager"},
		Data:       map[string][]byte{"secret-id": []byte("AKID"), "secret-key": []byte("KEY")},
	}
	cli := fake.NewClientBuilder().WithScheme(scheme).WithObjects(creds).Build()

	cred, err := ResolveCredential(context.Background(), cli, "tc-creds", "cert-manager")
	if err != nil {
		t.Fatalf("ResolveCredential: %v", err)
	}
	if cred == nil {
		t.Fatal("nil credential")
	}
	id, key, token := cred.GetCredential()
	if id != "AKID" || key != "KEY" || token != "" {
		t.Fatalf("got (%q,%q,%q), want (AKID,KEY,\"\")", id, key, token)
	}
}

func TestResolveCredential_StaticMissingSecretErrors(t *testing.T) {
	for _, k := range []string{"TKE_REGION", "TKE_PROVIDER_ID", "TKE_WEB_IDENTITY_TOKEN_FILE", "TKE_ROLE_ARN"} {
		t.Setenv(k, "")
	}
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	cli := fake.NewClientBuilder().WithScheme(scheme).Build()

	_, err := ResolveCredential(context.Background(), cli, "missing", "ns")
	if err == nil {
		t.Fatal("want error when secret missing")
	}
}

func TestLoadStaticCredentials_MissingKeys(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	creds := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "tc-creds", Namespace: "ns"},
		Data:       map[string][]byte{"secret-id": []byte("only-id")},
	}
	cli := fake.NewClientBuilder().WithScheme(scheme).WithObjects(creds).Build()

	if _, _, err := LoadStaticCredentials(context.Background(), cli, "tc-creds", "ns"); err == nil {
		t.Fatal("want error when secret-key missing")
	}
}
