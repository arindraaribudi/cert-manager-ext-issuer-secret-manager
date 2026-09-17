package awscert

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	certapi "github.com/arindraaribudi/cert-manager-ext-issuer-secret-manager/api/certificates/v1alpha1"
)

func TestLoadStaticCredentials_OK(t *testing.T) {
	s := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "aws-creds", Namespace: "ns"},
		Data: map[string][]byte{
			"access-key-id":     []byte("AKIA"),
			"secret-access-key": []byte("secret"),
		},
	}
	scheme := runtime.NewScheme()
	corev1.AddToScheme(scheme) //nolint:errcheck // test scheme bootstrap; AddToScheme only fails on duplicate registration
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(s).Build()
	cfg, err := LoadStaticCredentials(context.Background(), c, "aws-creds", "ns")
	if err != nil {
		t.Fatal(err)
	}
	// ponytail: region is set elsewhere (caller's spec.Region); static path returns empty.
	_ = cfg.Region
}

func TestLoadStaticCredentials_MissingKey(t *testing.T) {
	s := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "aws-creds", Namespace: "ns"},
		Data:       map[string][]byte{"access-key-id": []byte("AKIA")},
	}
	scheme := runtime.NewScheme()
	corev1.AddToScheme(scheme) //nolint:errcheck // test scheme bootstrap; AddToScheme only fails on duplicate registration
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(s).Build()
	if _, err := LoadStaticCredentials(context.Background(), c, "aws-creds", "ns"); err == nil {
		t.Error("want error when secret-access-key missing")
	}
}

func TestLoadPassphrase_Present(t *testing.T) {
	s := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "aws-creds", Namespace: "ns"},
		Data:       map[string][]byte{"passphrase": []byte("mysecret")},
	}
	scheme := runtime.NewScheme()
	corev1.AddToScheme(scheme) //nolint:errcheck // test scheme bootstrap; AddToScheme only fails on duplicate registration
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(s).Build()
	pp, err := LoadPassphrase(context.Background(), c, &certapi.AWSSecretRef{Name: "aws-creds"}, "ns")
	if err != nil {
		t.Fatal(err)
	}
	if pp != "mysecret" {
		t.Errorf("want mysecret, got %q", pp)
	}
}

func TestLoadPassphrase_NilRef(t *testing.T) {
	pp, err := LoadPassphrase(context.Background(), nil, nil, "ns")
	if err != nil {
		t.Fatal(err)
	}
	if pp != "" {
		t.Errorf("want empty passphrase for nil ref, got %q", pp)
	}
}
