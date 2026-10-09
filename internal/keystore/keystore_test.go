package keystore

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	ks "github.com/pavlo-v-chernykh/keystore-go/v4"
	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

func TestReuseOrGeneratePassword_ReusesWhenFingerprintMatches(t *testing.T) {
	cert := []byte("cert-bytes-1")
	key := []byte("key-bytes-1")
	existing := base64.StdEncoding.EncodeToString([]byte("previous-password-24-bytes"))

	secret := &corev1.Secret{
		Data: map[string][]byte{
			"tls.crt":           cert,
			"tls.key":           key,
			"keystore.password": []byte(existing),
		},
	}

	got, err := reuseOrGeneratePassword(cert, key, secret)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != existing {
		t.Fatalf("password = %q, want reuse of %q", got, existing)
	}
}

func TestReuseOrGeneratePassword_RotatesWhenCertChanges(t *testing.T) {
	existing := []byte("previous-password-24-bytes-b64")
	secret := &corev1.Secret{
		Data: map[string][]byte{
			"tls.crt":           []byte("OLD-cert-bytes"),
			"tls.key":           []byte("OLD-key-bytes"),
			"keystore.password": existing,
		},
	}

	got, err := reuseOrGeneratePassword([]byte("NEW-cert-bytes"), []byte("NEW-key-bytes"), secret)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) == string(existing) {
		t.Fatalf("password not rotated; got %q", got)
	}
}

func TestReuseOrGeneratePassword_GeneratesWhenNoExisting(t *testing.T) {
	got, err := reuseOrGeneratePassword([]byte("c"), []byte("k"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) == 0 {
		t.Fatal("empty password")
	}
	if len(got) < 24 {
		t.Fatalf("password too short: %d chars", len(got))
	}
	got2, _ := reuseOrGeneratePassword([]byte("c"), []byte("k"), nil)
	if bytes.Equal(got, got2) {
		t.Fatal("two fresh generations collided; rand broken?")
	}
}

// mustTestCert generates a self-signed ECDSA cert + key for use in
// round-trip tests. Returns cert PEM and PKCS#8 key PEM.
func mustTestCert(t *testing.T, cn string) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:         true,
		BasicConstraintsValid: true,
		DNSNames:     []string{"example.com"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return
}

func TestBuildJKS_RoundTrip(t *testing.T) {
	certPEM, keyPEM := mustTestCert(t, "example.com")
	got, err := buildJKS(certPEM, keyPEM, nil, []byte("pw"))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) == 0 {
		t.Fatal("empty JKS")
	}

	parsed := ks.New()
	if err := parsed.Load(bytes.NewReader(got), []byte("pw")); err != nil {
		t.Fatalf("parse JKS: %v", err)
	}
	if !parsed.IsPrivateKeyEntry("example.com") {
		t.Fatal("private key entry missing under CN alias")
	}
}

func TestBuildPKCS12_RoundTrip(t *testing.T) {
	certPEM, keyPEM := mustTestCert(t, "example.com")
	got, err := buildPKCS12(certPEM, keyPEM, nil, []byte("pw"))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) == 0 {
		t.Fatal("empty PKCS12")
	}
	privKey, leaf, caCerts, err := pkcs12.DecodeChain(got, "pw")
	if err != nil {
		t.Fatalf("DecodeChain: %v", err)
	}
	if leaf.Subject.CommonName != "example.com" {
		t.Fatalf("CN = %q, want example.com", leaf.Subject.CommonName)
	}
	if privKey == nil {
		t.Fatal("nil private key")
	}
	if len(caCerts) != 0 {
		t.Fatalf("expected 0 caCerts, got %d", len(caCerts))
	}
}

func TestBuildPKCS12_RoundTripWithChain(t *testing.T) {
	certPEM, keyPEM := mustTestCert(t, "leaf.example.com")
	chainPEM, _ := mustTestCert(t, "intermediate.example.com")

	got, err := buildPKCS12(certPEM, keyPEM, chainPEM, []byte("pw"))
	if err != nil {
		t.Fatal(err)
	}
	_, _, caCerts, err := pkcs12.DecodeChain(got, "pw")
	if err != nil {
		t.Fatal(err)
	}
	if len(caCerts) != 1 {
		t.Fatalf("expected 1 caCert, got %d", len(caCerts))
	}
	if caCerts[0].Subject.CommonName != "intermediate.example.com" {
		t.Fatalf("chain CN = %q, want intermediate.example.com", caCerts[0].Subject.CommonName)
	}
}

func TestAliasFor_PrefersCN(t *testing.T) {
	certPEM, _ := mustTestCert(t, "leaf.example.com")
	leaf := mustParseLeaf(t, certPEM)
	if got := aliasFor(leaf); got != "leaf.example.com" {
		t.Fatalf("alias = %q, want leaf.example.com", got)
	}
}

func TestAliasFor_FallsBackToDNSName(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		DNSNames:     []string{"host.example.com", "alt.example.com"},
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	leaf, _ := x509.ParseCertificate(der)
	if got := aliasFor(leaf); got != "host.example.com" {
		t.Fatalf("alias = %q, want host.example.com (first DNS name)", got)
	}
}

func TestAliasFor_FallsBackToLiteral(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	leaf, _ := x509.ParseCertificate(der)
	if got := aliasFor(leaf); got != "leaf" {
		t.Fatalf("alias = %q, want leaf (literal fallback)", got)
	}
}

func TestParseChainDER_MultipleBlocks(t *testing.T) {
	a, _ := mustTestCert(t, "a")
	b, _ := mustTestCert(t, "b")
	combined := append(a, b...)
	certs, err := parseChainDER(combined)
	if err != nil {
		t.Fatal(err)
	}
	if len(certs) != 2 {
		t.Fatalf("got %d certs, want 2", len(certs))
	}
}

// TestParseChainDER_DedupsAndSkipsMalformed guards the contract: duplicate
// DER certs collapse to one entry (avoids bloated JKS trust entries +
// PKCS#12 chain), and malformed blocks no longer fail silently — they
// must not lose valid neighbours (regression for the silent-truncation
// bug found when the fixture's CertificateChain contained a no-separator
// cert block).
func TestParseChainDER_DedupsAndSkipsMalformed(t *testing.T) {
	goodA, _ := mustTestCert(t, "a")
	goodB, _ := mustTestCert(t, "b")
	// Duplicate goodA twice, then a malformed block (truncated DER),
	// then goodB again.
	truncated := []byte("-----BEGIN CERTIFICATE-----\nMIIBfakebadcertnotreallyvalid\n-----END CERTIFICATE-----\n")
	bundle := append(append(append(append([]byte{}, goodA...), goodB...), goodA...), truncated...)
	bundle = append(bundle, goodB...)

	certs, err := parseChainDER(bundle)
	if err != nil {
		t.Fatalf("parseChainDER: %v", err)
	}
	if len(certs) != 2 {
		t.Fatalf("got %d certs, want 2 (a, b — malformed skipped, duplicates dropped)", len(certs))
	}
}

func mustParseLeaf(t *testing.T, certPEM []byte) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode(certPEM)
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestBuild_HappyPath(t *testing.T) {
	certPEM, keyPEM := mustTestCert(t, "happy.example.com")
	jks, p12, pw, skipped, err := Build(certPEM, keyPEM, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if skipped {
		t.Fatal("skipped unexpectedly")
	}
	if len(jks) == 0 || len(p12) == 0 || len(pw) == 0 {
		t.Fatal("nil outputs on happy path")
	}
}

func TestBuild_SkippedOnMissingKey(t *testing.T) {
	certPEM, _ := mustTestCert(t, "nokey.example.com")
	jks, p12, pw, skipped, err := Build(certPEM, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !skipped {
		t.Fatal("expected skipped=true when key is empty")
	}
	if len(jks) != 0 || len(p12) != 0 || len(pw) != 0 {
		t.Fatal("expected nil outputs when skipped")
	}
}

func TestBuild_GarbageCertReturnsErr(t *testing.T) {
	_, _, _, _, err := Build([]byte("not pem"), []byte("also not pem"), nil, nil)
	if err == nil {
		t.Fatal("expected error for garbage cert")
	}
}

func TestBuild_PasswordReuse(t *testing.T) {
	certPEM, keyPEM := mustTestCert(t, "reuse.example.com")
	existing := base64.StdEncoding.EncodeToString([]byte("stale-24-bytes-password"))
	secret := &corev1.Secret{
		Data: map[string][]byte{
			"tls.crt":           certPEM,
			"tls.key":           keyPEM,
			"keystore.password": []byte(existing),
		},
	}
	_, _, pw, _, err := Build(certPEM, keyPEM, nil, secret)
	if err != nil {
		t.Fatal(err)
	}
	if string(pw) != existing {
		t.Fatalf("password not reused; got %q want %q", pw, existing)
	}
}

// TestBuildTruststore_RoundTrip verifies the truststore-only JKS: only
// TrustedCertificateEntry values, no PrivateKeyEntry, loads with the empty
// password (Java's KeyStore.load(stream, "") accepts it).
func TestBuildTruststore_RoundTrip(t *testing.T) {
	a, _ := mustTestCert(t, "intermediate.example.com")
	b, _ := mustTestCert(t, "root.example.com")
	chainPEM := append(append([]byte{}, a...), b...)

	ts, err := BuildTruststore(chainPEM)
	if err != nil {
		t.Fatal(err)
	}
	if len(ts) == 0 {
		t.Fatal("empty truststore")
	}

	store := ks.New()
	if err := store.Load(bytes.NewReader(ts), nil); err != nil {
		t.Fatalf("load truststore: %v", err)
	}
	aliases := store.Aliases()
	if len(aliases) != 2 {
		t.Fatalf("got %d aliases, want 2 (chain-0, chain-1): %v", len(aliases), aliases)
	}
	for _, a := range aliases {
		if store.IsPrivateKeyEntry(a) {
			t.Fatalf("alias %q unexpectedly a PrivateKeyEntry (truststore must be keyless)", a)
		}
		if !store.IsTrustedCertificateEntry(a) {
			t.Fatalf("alias %q not a TrustedCertificateEntry", a)
		}
	}
}

// TestBuildTruststore_EmptyChainReturnsNil guards the contract: callers in
// chain-only mode depend on a nil return to skip the truststore.jks write
// rather than shipping an empty JKS that consumers can't tell apart from
// a successful build.
func TestBuildTruststore_EmptyChainReturnsNil(t *testing.T) {
	ts, err := BuildTruststore(nil)
	if err != nil {
		t.Fatal(err)
	}
	if ts != nil {
		t.Fatalf("want nil for empty chain, got %d bytes", len(ts))
	}
}