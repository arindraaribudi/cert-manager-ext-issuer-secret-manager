package keystore_test

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ks "github.com/pavlo-v-chernykh/keystore-go/v4"
	pkcs12 "software.sslmate.com/src/go-pkcs12"
	"sigs.k8s.io/yaml"

	"github.com/arindraaribudi/cert-manager-ext-issuer-secret-manager/internal/keystore"
)

// smPayload mirrors the upstream source payload shape (see COMPONENTS.md):
// "certificate" is the leaf, "certificate_chain" is the CA bundle only
// (the leaf is NOT repeated inside certificate_chain — that's a
// kubernetes.io/tls Secret convention, not the SM payload one).
type smPayload struct {
	Certificate      string `json:"certificate"`
	PrivateKey       string `json:"private_key"`
	CertificateChain string `json:"certificate_chain"`
}

// dummySource returns a generated leaf + key + chain wrapped in the SM
// payload shape. In-test fixture: keeps the test self-contained, no
// tt/jks files needed.
func dummySource(t *testing.T) smPayload {
	t.Helper()
	leafCert, leafKey := mustGenCert(t, "esb-nonprod-user", false)
	ca1 := mustGenCA(t, "caroot")
	ca2 := mustGenCA(t, "caroot2")
	leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafCert.Raw})
	keyDER, err := x509.MarshalPKCS8PrivateKey(leafKey)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	chainPEM := bytes.Join([][]byte{
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca1.Raw}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca2.Raw}),
	}, nil)
	return smPayload{
		Certificate:      string(leafPEM),
		PrivateKey:       string(keyPEM),
		CertificateChain: string(chainPEM),
	}
}

// TestBuildFromFixture generates a dummy SM payload in-test, runs
// keystore.Build, and round-trips the resulting JKS. Output YAML is
// written to t.TempDir() (was tt/jks/secret.generated.yaml — removed
// to keep fixtures out of the repo).
func TestBuildFromFixture(t *testing.T) {
	f := dummySource(t)

	leafPEM := []byte(f.Certificate)
	chainPEM := []byte(f.CertificateChain)
	if len(leafPEM) == 0 || len(chainPEM) == 0 {
		t.Fatalf("dummy source missing leaf or chain")
	}

	jks, p12, pw, skipped, err := keystore.Build(leafPEM, []byte(f.PrivateKey), chainPEM, nil)
	if err != nil {
		t.Fatalf("keystore.Build: %v", err)
	}
	if skipped {
		t.Fatal("keystore.Build reported skipped — private key missing?")
	}
	if err := keystore.ParseJKSForTest(jks, pw); err != nil {
		t.Fatalf("JKS round-trip: %v", err)
	}

	secret := &corev1.Secret{
		APIVersion: "v1",
		Kind:       "Secret",
		ObjectMeta: metav1.ObjectMeta{
			Name:      "esb-nonprod-user",
			Namespace: "default",
		},
		Type: corev1.SecretTypeTLS,
		Data: map[string][]byte{
			"tls.crt":           append([]byte(f.Certificate), []byte(f.CertificateChain)...),
			"tls.key":           []byte(f.PrivateKey),
			"keystore.jks":      jks,
			"keystore.p12":      p12,
			"keystore.password": pw,
		},
	}

	doc, err := yaml.Marshal(secret)
	if err != nil {
		t.Fatalf("yaml.Marshal: %v", err)
	}
	outPath := filepath.Join(t.TempDir(), "secret.generated.yaml")
	if err := os.WriteFile(outPath, doc, 0o600); err != nil {
		t.Fatalf("write %s: %v", outPath, err)
	}

	t.Logf("wrote %s (%d bytes)", outPath, len(doc))
	for _, k := range []string{"tls.crt", "tls.key", "keystore.jks", "keystore.p12", "keystore.password"} {
		t.Logf("  %-18s  %d bytes", k, len(secret.Data[k]))
	}
}

// TestBuildFromFixture_ContentValid drives the dummy source through
// keystore.Build and asserts every artifact in the resulting Secret
// round-trips into something a real consumer (TLS server, JVM with
// truststore, openssl pkcs12) would accept. Failure here means the
// generated Secret would not work in production.
func TestBuildFromFixture_ContentValid(t *testing.T) {
	f := dummySource(t)

	leafPEM := []byte(f.Certificate)
	chainPEM := []byte(f.CertificateChain)
	jks, p12, pw, _, err := keystore.Build(leafPEM, []byte(f.PrivateKey), chainPEM, nil)
	if err != nil {
		t.Fatalf("keystore.Build: %v", err)
	}

	// tls.crt in a kubernetes.io/tls Secret holds leaf + chain (k8s convention).
	tlsCrt := append([]byte(f.Certificate), []byte(f.CertificateChain)...)
	tlsKey := []byte(f.PrivateKey)

	t.Run("tls.crt parses as X.509", func(t *testing.T) {
		leaf, err := parseFirstCert(tlsCrt)
		if err != nil {
			t.Fatalf("first cert: %v", err)
		}
		chainCerts, err := parseAllCerts(tlsCrt)
		if err != nil {
			t.Fatalf("chain: %v", err)
		}
		if len(chainCerts) < 2 {
			t.Fatalf("expected leaf + at least one CA in tls.crt, got %d blocks", len(chainCerts))
		}
		if cn := leaf.Subject.CommonName; cn == "" {
			t.Fatal("leaf has empty CN")
		}
		t.Logf("leaf CN=%q, chain=%d blocks", leaf.Subject.CommonName, len(chainCerts))
	})

	t.Run("tls.key parses as PKCS#8", func(t *testing.T) {
		block, _ := pem.Decode(tlsKey)
		if block == nil {
			t.Fatal("not PEM")
		}
		if block.Type != "PRIVATE KEY" {
			t.Fatalf("expected PKCS#8 (got %q)", block.Type)
		}
		if _, err := x509.ParsePKCS8PrivateKey(block.Bytes); err != nil {
			t.Fatalf("ParsePKCS8PrivateKey: %v", err)
		}
	})

	t.Run("keystore.password decodes to 24 raw bytes", func(t *testing.T) {
		raw, err := base64.StdEncoding.DecodeString(string(pw))
		if err != nil {
			t.Fatalf("base64 decode: %v", err)
		}
		if len(raw) != 24 {
			t.Fatalf("expected 24 raw bytes, got %d", len(raw))
		}
	})

	t.Run("JKS loads + entries match input", func(t *testing.T) {
		store := ks.New()
		if err := store.Load(bytes.NewReader(jks), pw); err != nil {
			t.Fatalf("JKS Load: %v", err)
		}
		aliases := store.Aliases()
		var privKeyAliases, trustAliases []string
		for _, a := range aliases {
			switch {
			case store.IsPrivateKeyEntry(a):
				privKeyAliases = append(privKeyAliases, a)
			case store.IsTrustedCertificateEntry(a):
				trustAliases = append(trustAliases, a)
			}
		}
		if len(privKeyAliases) != 1 {
			t.Fatalf("expected 1 private-key entry, got %d (%v)", len(privKeyAliases), privKeyAliases)
		}
		if len(trustAliases) < 1 {
			t.Fatalf("expected ≥1 trusted-cert entries (chain), got 0")
		}
		entry, err := store.GetPrivateKeyEntry(privKeyAliases[0], pw)
		if err != nil {
			t.Fatalf("GetPrivateKeyEntry: %v", err)
		}
		if len(entry.PrivateKey) == 0 {
			t.Fatal("PrivateKeyEntry missing DER bytes")
		}
		expectedCN, _ := parseFirstCert(tlsCrt)
		if privKeyAliases[0] != expectedCN.Subject.CommonName {
			t.Fatalf("alias=%q, want CN=%q", privKeyAliases[0], expectedCN.Subject.CommonName)
		}
		t.Logf("JKS: 1 privkey entry alias=%q, %d trust entries", privKeyAliases[0], len(trustAliases))
	})

	t.Run("PKCS#12 decodes + chain matches", func(t *testing.T) {
		key, leaf, caCerts, err := pkcs12.DecodeChain(p12, string(pw))
		if err != nil {
			t.Fatalf("pkcs12.DecodeChain: %v", err)
		}
		if key == nil {
			t.Fatal("p12 missing key")
		}
		if leaf == nil {
			t.Fatal("p12 missing leaf cert")
		}
		if len(caCerts) < 1 {
			t.Fatalf("expected ≥1 CA in p12 chain, got %d", len(caCerts))
		}
		want, _ := parseFirstCert(tlsCrt)
		if !bytes.Equal(leaf.Raw, want.Raw) {
			t.Fatalf("p12 leaf (%x) != tls.crt leaf (%x)", leaf.Raw[:8], want.Raw[:8])
		}
		wantKeyBlock, _ := pem.Decode(tlsKey)
		if _, err := x509.ParsePKCS8PrivateKey(wantKeyBlock.Bytes); err != nil {
			t.Fatalf("tls.key PKCS8: %v", err)
		}
		p12KeyDER, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			t.Fatalf("MarshalPKCS8PrivateKey(p12 key): %v", err)
		}
		if _, err := x509.ParsePKCS8PrivateKey(p12KeyDER); err != nil {
			t.Fatalf("p12 key not PKCS#8 DER: %v", err)
		}
		t.Logf("P12: leaf CN=%q, %d CA certs", leaf.Subject.CommonName, len(caCerts))
	})
}

func parseFirstCert(pemBytes []byte) (*x509.Certificate, error) {
	rest := pemBytes
	for {
		block, r := pem.Decode(rest)
		if block == nil {
			return nil, errNoCert{}
		}
		rest = r
		if block.Type != "CERTIFICATE" {
			continue
		}
		return x509.ParseCertificate(block.Bytes)
	}
}

func parseAllCerts(pemBytes []byte) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	rest := pemBytes
	for {
		block, r := pem.Decode(rest)
		if block == nil {
			break
		}
		rest = r
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, nil
}

type errNoCert struct{}

func (errNoCert) Error() string { return "no CERTIFICATE block found" }

// mustGenCert generates a throw-away self-signed cert for tests.
func mustGenCert(t *testing.T, cn string, isCA bool) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  isCA,
		BasicConstraintsValid: isCA,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c, key
}

// mustGenCA is a one-liner wrapper for a self-signed root CA.
func mustGenCA(t *testing.T, cn string) *x509.Certificate {
	t.Helper()
	c, _ := mustGenCert(t, cn, true)
	return c
}
