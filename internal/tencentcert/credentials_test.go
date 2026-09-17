package tencentcert

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestLoadStaticCredentials_OK(t *testing.T) {
	s := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "tc-creds", Namespace: "ns"},
		Data: map[string][]byte{
			"secret-id":  []byte("AKID"),
			"secret-key": []byte("KEY"),
		},
	}
	scheme := runtime.NewScheme()
	corev1.AddToScheme(scheme) //nolint:errcheck // test scheme bootstrap; AddToScheme only fails on duplicate registration
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(s).Build()
	id, key, err := LoadStaticCredentials(context.Background(), c, "tc-creds", "ns")
	if err != nil {
		t.Fatal(err)
	}
	if id != "AKID" || key != "KEY" {
		t.Errorf("got id=%s key=%s", id, key)
	}
}

func TestLoadStaticCredentials_MissingKey(t *testing.T) {
	s := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "tc-creds", Namespace: "ns"},
		Data:       map[string][]byte{"secret-id": []byte("AKID")},
	}
	scheme := runtime.NewScheme()
	corev1.AddToScheme(scheme) //nolint:errcheck // test scheme bootstrap; AddToScheme only fails on duplicate registration
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(s).Build()
	if _, _, err := LoadStaticCredentials(context.Background(), c, "tc-creds", "ns"); err == nil {
		t.Error("want error when secret-key missing")
	}
}
