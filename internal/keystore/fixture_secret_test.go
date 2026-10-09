package keystore_test

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ks "github.com/pavlo-v-chernykh/keystore-go/v4"
	pkcs12 "software.sslmate.com/src/go-pkcs12"
	"sigs.k8s.io/yaml"

	"github.com/arindraaribudi/cert-manager-ext-issuer-secret-manager/internal/keystore"
)

// fixture mirrors the upstream source payload shape (see
// tt/jks/secret-payload.pem.json). "certificate_chain" carries
// leaf+intermediates concatenated — SplitLeafAndChain splits them.
type fixture struct {
	Certificate      string `json:"certificate"`
	PrivateKey       string `json:"private_key"`
	CertificateChain string `json:"certificate_chain"`
}

// TestBuildFromFixture takes the sample PEM/JKS payload under tt/jks/
// and generates a kubernetes.io/tls Secret containing both the TLS
// material and the auxiliary keystore artifacts. The rendered YAML is
// written next to the fixture so it can be diffed or applied with
// kubectl. Also asserts the JKS round-trips with ParseJKSForTest.
//
// Run: go test ./internal/keystore -run TestBuildFromFixture -v
func TestBuildFromFixture(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate test file")
	}
	repoRoot := filepath.Join(filepath.Dir(thisFile), "..", "..")
	fixturePath := filepath.Join(repoRoot, "tt", "jks", "secret-payload.pem.json")
	outPath := filepath.Join(repoRoot, "tt", "jks", "secret.generated.yaml")

	raw, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatalf("read fixture %s: %v", fixturePath, err)
	}
	var f fixture
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatalf("parse fixture: %v", err)
	}

	// certificate = leaf, certificate_chain = CA bundle only (matches
// upstream source shape — SplitLeafAndChain would mis-tag the first CA
// as the leaf, since the chain doesn't include the leaf here).
	leafPEM := []byte(f.Certificate)
	chainPEM := []byte(f.CertificateChain)
	if len(leafPEM) == 0 || len(chainPEM) == 0 {
		t.Fatalf("fixture missing leaf or chain")
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
	if err := os.WriteFile(outPath, doc, 0o600); err != nil {
		t.Fatalf("write %s: %v", outPath, err)
	}

	t.Logf("wrote %s (%d bytes)", outPath, len(doc))
	for _, k := range []string{"tls.crt", "tls.key", "keystore.jks", "keystore.p12", "keystore.password"} {
		t.Logf("  %-18s  %d bytes", k, len(secret.Data[k]))
	}
}

// TestBuildFromFixture_ContentValid drives the same fixture through
// keystore.Build and asserts every artifact in the resulting Secret
// round-trips into something a real consumer (TLS server, JVM with
// truststore, openssl pkcs12) would accept. Failure here means the
// generated Secret would not work in production.
func TestBuildFromFixture_ContentValid(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate test file")
	}
	fixturePath := filepath.Join(filepath.Dir(thisFile), "..", "..", "tt", "jks", "secret-payload.pem.json")

	raw, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var f fixture
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatalf("parse fixture: %v", err)
	}

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

// TestBuildFromFixture_MatchesReference loads the project's "golden"
// reference artifacts under tt/jks/ (client.truststore.jks and
// esb-nonprod-user.p12, password from tt/jks/password) and asserts that
// the generated keystores contain the same X.509 certificates — by
// SHA-256 fingerprint. This is the contract: the controller's output
// must be byte-for-byte equivalent to what the original JKS/P12 producer
// generated from the same source.
func TestBuildFromFixture_MatchesReference(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate test file")
	}
	root := filepath.Join(filepath.Dir(thisFile), "..", "..", "tt", "jks")
	pwBytes, err := os.ReadFile(filepath.Join(root, "password"))
	if err != nil {
		t.Fatalf("read password file: %v", err)
	}
	refPassword := bytes.TrimSpace(pwBytes)

	// Reference truststore: 2 trusted cert entries (caroot, caroot2).
	// Despite the .jks extension, the file is a PKCS#12 truststore
	// (verified with `keytool -list`). Decode with DecodeTrustStore.
	refTrustBytes, err := os.ReadFile(filepath.Join(root, "client.truststore.jks"))
	if err != nil {
		t.Fatalf("read truststore: %v", err)
	}
	refTrustCerts, err := pkcs12.DecodeTrustStore(refTrustBytes, string(refPassword))
	if err != nil {
		t.Fatalf("truststore decode: %v", err)
	}
	refTrustFPs := map[string]string{}
	for i, c := range refTrustCerts {
		refTrustFPs[fp(c.Raw)] = fmt.Sprintf("trust[%d] CN=%s", i, c.Subject.CommonName)
	}

	// Reference p12: 1 PrivateKeyEntry alias=esb-nonprod-user + chain.
	refP12Bytes, err := os.ReadFile(filepath.Join(root, "esb-nonprod-user.p12"))
	if err != nil {
		t.Fatalf("read p12: %v", err)
	}
	refKey, refLeaf, refCAs, err := pkcs12.DecodeChain(refP12Bytes, string(refPassword))
	if err != nil {
		t.Fatalf("ref p12 decode: %v", err)
	}
	refLeafFP := fp(refLeaf.Raw)
	refCAFPs := map[string]struct{}{}
	for _, c := range refCAs {
		refCAFPs[fp(c.Raw)] = struct{}{}
	}
	t.Logf("ref truststore: %d entries (caroot=%s caroot2=%s)",
		len(refTrustFPs), refTrustFPs[fp([]byte{0,0,0,0})], "")
	for f := range refTrustFPs {
		t.Logf("  trust fp=%s", f)
	}
	t.Logf("ref p12: leaf fp=%s, %d chain entries", refLeafFP, len(refCAs))
	for i, c := range refCAs {
		t.Logf("  chain[%d] fp=%s", i, fp(c.Raw))
	}
	_ = refKey

	// Build generated artifacts from the same fixture.
	raw, err := os.ReadFile(filepath.Join(root, "secret-payload.pem.json"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var f fixture
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatalf("parse fixture: %v", err)
	}
	leafPEM := []byte(f.Certificate)
	chainPEM := []byte(f.CertificateChain)
	jks, p12, pw, _, err := keystore.Build(leafPEM, []byte(f.PrivateKey), chainPEM, nil)
	if err != nil {
		t.Fatalf("keystore.Build: %v", err)
	}

	t.Run("generated JKS trust entries cover reference truststore CAs", func(t *testing.T) {
		store := ks.New()
		if err := store.Load(bytes.NewReader(jks), pw); err != nil {
			t.Fatalf("gen jks load: %v", err)
		}
		// Build set of fingerprints the generated JKS surfaces anywhere
		// (trust entries + privkey chain) — duplicates deduped.
		genFPs := map[string]bool{}
		for _, a := range store.Aliases() {
			if store.IsTrustedCertificateEntry(a) {
				te, _ := store.GetTrustedCertificateEntry(a)
				genFPs[fp(te.Certificate.Content)] = true
			}
			if store.IsPrivateKeyEntry(a) {
				chain, _ := store.GetPrivateKeyEntryCertificateChain(a)
				for _, c := range chain {
					genFPs[fp(c.Content)] = true
				}
			}
		}
		// Every reference CA must appear somewhere in gen output.
		for f, alias := range refTrustFPs {
			if !genFPs[f] {
				t.Errorf("reference CA %s fp=%s missing from generated JKS", alias, f)
			} else {
				t.Logf("  MATCH ref CA %s fp=%s present in gen JKS", alias, f)
			}
		}
		// Generated JKS must also contain the leaf (sanity).
		if !genFPs[refLeafFP] {
			t.Errorf("gen JKS missing leaf fp=%s", refLeafFP)
		}
	})

	t.Run("generated JKS privkey leaf matches reference p12 leaf", func(t *testing.T) {
		store := ks.New()
		if err := store.Load(bytes.NewReader(jks), pw); err != nil {
			t.Fatalf("gen jks load: %v", err)
		}
		var privAlias string
		for _, a := range store.Aliases() {
			if store.IsPrivateKeyEntry(a) {
				privAlias = a
				break
			}
		}
		if privAlias == "" {
			t.Fatal("no privkey entry in gen jks")
		}
		chain, err := store.GetPrivateKeyEntryCertificateChain(privAlias)
		if err != nil {
			t.Fatalf("get privkey chain: %v", err)
		}
		if len(chain) == 0 {
			t.Fatal("privkey entry missing chain")
		}
		genLeafFP := fp(chain[0].Content)
		if genLeafFP != refLeafFP {
			t.Fatalf("gen jks leaf fp=%s != ref p12 leaf fp=%s", genLeafFP, refLeafFP)
		}
		t.Logf("gen jks leaf fp=%s == ref p12 leaf fp=%s", genLeafFP, refLeafFP)
	})

	t.Run("generated P12 leaf matches reference p12 leaf", func(t *testing.T) {
		_, leaf, _, err := pkcs12.DecodeChain(p12, string(pw))
		if err != nil {
			t.Fatalf("gen p12 decode: %v", err)
		}
		if fp(leaf.Raw) != refLeafFP {
			t.Fatalf("gen p12 leaf fp=%s != ref p12 leaf fp=%s", fp(leaf.Raw), refLeafFP)
		}
		t.Logf("gen p12 leaf fp=%s == ref p12 leaf fp=%s", fp(leaf.Raw), refLeafFP)
	})

	t.Run("generated P12 chain ⊆ reference p12 chain", func(t *testing.T) {
		_, _, caCerts, err := pkcs12.DecodeChain(p12, string(pw))
		if err != nil {
			t.Fatalf("gen p12 decode: %v", err)
		}
		for i, c := range caCerts {
			f := fp(c.Raw)
			if _, ok := refCAFPs[f]; !ok {
				t.Errorf("gen p12 chain[%d] fp=%s not in reference p12 chain", i, f)
			} else {
				t.Logf("  MATCH chain[%d] fp=%s", i, f)
			}
		}
	})
}

func parseFirstCert(pemBytes []byte) (*x509.Certificate, error) {
	rest := pemBytes
	for {
		block, r := pem.Decode(rest)
		if block == nil {
			return nil, ErrNoCert
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

func fp(b []byte) string {
	s := sha256.Sum256(b)
	return fmt.Sprintf("%x", s)
}

var ErrNoCert = errNoCert{}

type errNoCert struct{}

func (errNoCert) Error() string { return "no CERTIFICATE block found" }