// Command demo proves the controller's fetch + parse + secret-build pipeline
// end-to-end against the fake, for whichever cloud provider is selected via
// -provider. ponytail: non-trivial logic leaves one runnable check; this is it.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	api "github.com/arindraaribudi/cert-manager-ext-issuer-secret-manager/api/v1alpha1"
	awssm "github.com/arindraaribudi/cert-manager-ext-issuer-secret-manager/internal/aws/fake"
	"github.com/arindraaribudi/cert-manager-ext-issuer-secret-manager/internal/controller"
	gcpsm "github.com/arindraaribudi/cert-manager-ext-issuer-secret-manager/internal/gcp/fake"
	tencentsm "github.com/arindraaribudi/cert-manager-ext-issuer-secret-manager/internal/tencent/fake"
)

// fakeClient is the common shape of the aws/gcp/tencent fake secret-manager clients.
type fakeClient interface {
	Set(ref string, payload []byte)
	Fetch(ctx context.Context, ref string) ([]byte, error)
}

func main() {
	provider := flag.String("provider", "aws", "one of: aws, gcp, tencent")
	flag.Parse()
	if err := run(*provider); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(provider string) error {
	ctx := context.Background()

	var fc fakeClient
	var ref string
	switch provider {
	case "aws":
		fc, ref = awssm.New(), "demo-secret"
	case "gcp":
		fc, ref = gcpsm.New(), "projects/p/secrets/s/versions/latest"
	case "tencent":
		fc, ref = tencentsm.New(), "abc123"
	default:
		return fmt.Errorf("unknown provider %q", provider)
	}

	cert := []byte("-----BEGIN CERTIFICATE-----MOCKCERT-----END CERTIFICATE-----")
	key := []byte("-----BEGIN PRIVATE KEY-----MOCKKEY-----END PRIVATE KEY-----")
	chain := []byte("-----BEGIN CERTIFICATE-----MOCKCHAIN-----END CERTIFICATE-----")
	payload, _ := json.Marshal(map[string]string{
		"certificate":       string(cert),
		"private_key":       string(key),
		"certificate_chain": string(chain),
	})
	fc.Set(ref, payload)

	got, err := fc.Fetch(ctx, ref)
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
	fmt.Printf("%s: built Secret %s/%s with %d cert bytes, %d key bytes, %d chain bytes\n",
		provider,
		secret.Namespace, secret.Name,
		len(secret.Data[corev1.TLSCertKey]),
		len(secret.Data[corev1.TLSPrivateKeyKey]),
		len(secret.Data[corev1.ServiceAccountRootCAKey]),
	)
	return nil
}
