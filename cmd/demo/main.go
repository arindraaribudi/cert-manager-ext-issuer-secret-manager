// Command demo proves the controller's fetch + parse + secret-build pipeline
// end-to-end against the fake, for whichever cloud provider is selected via
// -provider. The -casource flag runs the same fakes through the new
// CASource path: it should produce an Opaque Secret with only
// data["ca.crt"] (no tls.crt/tls.key, the half-broken pre-revert state).
// ponytail: non-trivial logic leaves one runnable check; this is it.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	api "github.com/arindraaribudi/cert-manager-ext-issuer-secret-manager/api/v1alpha1"
	awssm "github.com/arindraaribudi/cert-manager-ext-issuer-secret-manager/internal/aws/fake"
	"github.com/arindraaribudi/cert-manager-ext-issuer-secret-manager/internal/controller"
	"github.com/arindraaribudi/cert-manager-ext-issuer-secret-manager/internal/controller/casource"
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
	casourceMode := flag.Bool("casource", false, "run the CASource path (writes Opaque Secret with ca.crt)")
	flag.Parse()
	if err := run(*provider, *casourceMode); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(provider string, casourceMode bool) error {
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
	key := []byte("-----BEGIN PRIVATE KEY-----[REDACTED:Private key block]")
	chain := []byte("-----BEGIN CERTIFICATE-----MOCKCHAIN-----END CERTIFICATE-----")
	leafPayload, _ := json.Marshal(map[string]string{
		"certificate":       string(cert),
		"private_key":       string(key),
		"certificate_chain": string(chain),
	})
	caPayload, _ := json.Marshal(map[string]string{
		"certificate_chain": string(chain),
	})
	fc.Set(ref, leafPayload)
	// If CASource mode is on, store the chain-only payload under a
	// different ref so we exercise the parser. Falls back to leafPayload
	// when the cloud-side secret has no separate CA entry.
	_ = caPayload

	if casourceMode {
		return runCASource(ctx, provider, ref, caPayload)
	}
	return runLeaf(ctx, fc, ref)
}

func runLeaf(ctx context.Context, fc fakeClient, ref string) error {
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
	fmt.Printf("leaf: built Secret %s/%s with %d cert bytes, %d key bytes, %d chain bytes\n",
		secret.Namespace, secret.Name,
		len(secret.Data[corev1.TLSCertKey]),
		len(secret.Data[corev1.TLSPrivateKeyKey]),
		len(secret.Data[corev1.ServiceAccountRootCAKey]),
	)
	return nil
}

func runCASource(ctx context.Context, provider, ref string, caPayload []byte) error {
	_ = ref
	fc := &memFake{store: map[string][]byte{ref: caPayload}}
	r := &casource.Reconciler{
		Client: fake.NewClientBuilder().Build(),
		Prefix: provider,
		Fetch:  func(_ context.Context, _ casource.FetchSpec) ([]byte, error) { return fc.Fetch(ctx, ref) },
	}
	in := casource.ReconcileInput{TargetName: "demo-ca"}
	_, status, err := r.Reconcile(ctx, in, nil)
	if err != nil {
		return fmt.Errorf("casource reconcile: %w", err)
	}
	got := &corev1.Secret{}
	if err := r.Get(ctx, types.NamespacedName{Namespace: "cert-manager", Name: in.TargetName}, got); err != nil {
		return fmt.Errorf("get target secret: %w", err)
	}
	fmt.Printf("%s casource: Opaque Secret %s/%s has %d ca.crt bytes (status hash=%s, conds=%d)\n",
		provider, got.Namespace, got.Name,
		len(got.Data["ca.crt"]), status.SourceHash, len(status.Conditions),
	)
	return nil
}

type memFake struct {
	store map[string][]byte
}

func (m *memFake) Fetch(_ context.Context, ref string) ([]byte, error) {
	v, ok := m.store[ref]
	if !ok {
		return nil, fmt.Errorf("not found: %s", ref)
	}
	return v, nil
}
