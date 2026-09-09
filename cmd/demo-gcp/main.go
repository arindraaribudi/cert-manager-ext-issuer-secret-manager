// Command demo-gcp proves the controller's fetch + parse + secret-build pipeline
// end-to-end against the fake. ponytail: non-trivial logic leaves one runnable
// check; this is it for the GCP path.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	api "github.com/arindraaribudi/cert-manager-ext-issuer-secret-manager/api/v1alpha1"
	gcpsm "github.com/arindraaribudi/cert-manager-ext-issuer-secret-manager/internal/gcp/fake"
	"github.com/arindraaribudi/cert-manager-ext-issuer-secret-manager/internal/controller"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	ctx := context.Background()
	fc := gcpsm.New()
	cert := []byte("-----BEGIN CERTIFICATE-----MOCKCERT-----END CERTIFICATE-----")
	key := []byte("-----BEGIN PRIVATE KEY-----MOCKKEY-----END PRIVATE KEY-----")
	chain := []byte("-----BEGIN CERTIFICATE-----MOCKCHAIN-----END CERTIFICATE-----")
	payload, _ := json.Marshal(map[string]string{
		"certificate": string(cert),
		"private_key": string(key),
		"certificate_chain": string(chain),
	})
	fc.Set("projects/p/secrets/s/versions/latest", payload)

	got, err := fc.Fetch(ctx, "projects/p/secrets/s/versions/latest")
	if err != nil {
		return fmt.Errorf("fetch: %w", err)
	}
	parsed, err := controller.Extract(got, api.PayloadKeys{})
	if err != nil {
		return fmt.Errorf("extract: %w", err)
	}

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "app-tls", Namespace: "demo"},
		Type:       corev1.SecretTypeTLS,
		Data: map[string][]byte{
			corev1.TLSCertKey:              parsed.Certificate,
			corev1.TLSPrivateKeyKey:        parsed.PrivateKey,
			corev1.ServiceAccountRootCAKey: parsed.Chain,
		},
	}
	fmt.Printf("gcp: built Secret %s/%s with %d cert bytes, %d key bytes, %d chain bytes\n",
		secret.Namespace, secret.Name,
		len(secret.Data[corev1.TLSCertKey]),
		len(secret.Data[corev1.TLSPrivateKeyKey]),
		len(secret.Data[corev1.ServiceAccountRootCAKey]),
	)
	return nil
}
