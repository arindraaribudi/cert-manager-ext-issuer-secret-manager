package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

// TestJKS2Secret_RoundTripP12 exercises the loadSource + verifyPayload
// pair against the keyed reference fixture (esb-nonprod-user.p12).
// The fixture is actually PKCS#12 despite the .p12 extension, so
// loadSource MUST auto-detect it; the SM JSON payload produced from
// the parsed source MUST pass verifyPayload (leaf fingerprint,
// certificate_chain set, private_key DER).
func TestJKS2Secret_RoundTripP12(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate test file")
	}
	root := filepath.Join(filepath.Dir(thisFile), "..", "..", "tt", "jks")
	pwBytes, err := os.ReadFile(filepath.Join(root, "password"))
	if err != nil {
		t.Fatalf("read password: %v", err)
	}
	password := bytes.TrimRight(pwBytes, "\r\n")

	srcBytes, err := os.ReadFile(filepath.Join(root, "esb-nonprod-user.p12"))
	if err != nil {
		t.Fatalf("read source: %v", err)
	}

	sk, err := loadSource(srcBytes, password)
	if err != nil {
		t.Fatalf("loadSource: %v", err)
	}
	if sk.leaf == nil {
		t.Fatal("source has no leaf")
	}
	if len(sk.keyDER) == 0 {
		t.Fatal("source has no key — keyed p12 expected")
	}
	if sk.leaf.Subject.CommonName != "esb-nonprod-user" {
		t.Fatalf("leaf CN = %q, want esb-nonprod-user", sk.leaf.Subject.CommonName)
	}
	if len(sk.chain) != 2 {
		t.Fatalf("chain len = %d, want 2 unique CAs (caroot + caroot2)", len(sk.chain))
	}

	payload := buildPayload(sk)
	if err := verifyPayload(payload, sk, nil); err != nil {
		t.Fatalf("verifyPayload: %v", err)
	}
	t.Logf("round-trip OK: leaf + %d chain + key (%d bytes PKCS#8)", len(sk.chain), len(sk.keyDER))
}

// TestJKS2Secret_LoadSource_KeylessTruststore checks the auto-detect
// falls back to PKCS#12 (keystore-go rejects keyless PKCS#12 with
// "got invalid magic") and rejects the keyless case via Main, while
// loadSource itself returns a populated leaf + chain.
func TestJKS2Secret_LoadSource_KeylessTruststore(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate test file")
	}
	root := filepath.Join(filepath.Dir(thisFile), "..", "..", "tt", "jks")
	pwBytes, _ := os.ReadFile(filepath.Join(root, "password"))
	password := bytes.TrimRight(pwBytes, "\r\n")

	srcBytes, err := os.ReadFile(filepath.Join(root, "client.truststore.jks"))
	if err != nil {
		t.Fatalf("read truststore: %v", err)
	}
	sk, err := loadSource(srcBytes, password)
	if err != nil {
		t.Fatalf("loadSource: %v", err)
	}
	if sk.leaf == nil {
		t.Fatal("truststore promoted no leaf — fromJKS would have set one")
	}
	if len(sk.keyDER) != 0 {
		t.Fatal("truststore has a key — expected keyless")
	}
	if !sk.keyless {
		t.Fatal("keyless flag not set")
	}
	if len(sk.chain) == 0 {
		t.Fatal("truststore produced empty chain")
	}
	t.Logf("truststore: leaf CN=%q, %d chain certs (no key)", sk.leaf.Subject.CommonName, len(sk.chain))
}

// TestJKS2Secret_TruststoreMerge drives the Main pipeline (loadSource
// → truststore union → buildPayload → verifyPayload) against synthetic
// fixtures: a keyed PKCS#12 source + a keyless PKCS#12 truststore
// holding one extra CA. Verifies the extra CA flows into
// certificate_chain so consumers don't need a second payload to
// complete trust.
//
// We can't use the real tt/jks/client.truststore.jks here — it's
// RC2-40 encrypted PKCS#7 (the legacy "strong-encryption-disabled"
// mode Java's keytool still tolerates but go-pkcs12 refuses). The
// fixture is therefore generated in-test with a cipher go-pkcs12
// supports.
func TestJKS2Secret_TruststoreMerge(t *testing.T) {
	leafCert, leafKey := mustSelfSigned(t, "app.example.com")
	chainRoot := mustSelfSignedCA(t, "extra-root-CA")
	chainRootFP := fp(chainRoot.Raw)

	srcP12 := mustEncodeKeyedP12(t, leafCert, leafKey, nil, "srcpw")
	trustP12 := mustEncodeTrustStoreP12(t, []*x509.Certificate{chainRoot}, "trustpw")

	sk, err := loadSource(srcP12, []byte("srcpw"))
	if err != nil {
		t.Fatalf("loadSource source: %v", err)
	}
	ts, err := loadSource(trustP12, []byte("trustpw"))
	if err != nil {
		t.Fatalf("loadSource truststore: %v", err)
	}
	if !ts.keyless {
		t.Fatal("truststore fixture is keyed; expected keyless")
	}

	// Mimic Main's truststore union.
	seen := map[string]bool{fp(sk.leaf.Raw): true}
	for _, c := range sk.chain {
		seen[fp(c.Raw)] = true
	}
	truststoreFPs := map[string]bool{}
	for _, c := range append([]*x509.Certificate{ts.leaf}, ts.chain...) {
		f := fp(c.Raw)
		truststoreFPs[f] = true
		if !seen[f] {
			sk.chain = append(sk.chain, c)
			seen[f] = true
		}
	}
	if _, ok := truststoreFPs[chainRootFP]; !ok {
		t.Fatal("truststore fingerprint set missing the extra root")
	}

	payload := buildPayload(sk)
	if err := verifyPayload(payload, sk, truststoreFPs); err != nil {
		t.Fatalf("verifyPayload: %v", err)
	}
	t.Logf("merge OK: leaf + %d chain incl. 1 truststore root", len(sk.chain))
}

// buildPayload produces the SM JSON payload (certificate / private_key /
// certificate_chain PEM strings) from a parsed source. Mirrors the
// Main path without the keystore.Build call (the cloud payload doesn't
// carry JKS / P12 — only the cert-manager controller's kubernetes.io/tls
// Secret output does).
func buildPayload(sk *sourceKeystore) smPayload {
	p := smPayload{
		Certificate: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: sk.leaf.Raw})),
	}
	for _, c := range sk.chain {
		p.CertificateChain += string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}))
	}
	if len(sk.keyDER) > 0 {
		p.PrivateKey = string(pemEncodePKCS8(sk.keyDER))
	}
	return p
}

// mustSelfSigned generates a throw-away RSA cert for tests.
func mustSelfSigned(t *testing.T, cn string) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
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

// mustSelfSignedCA generates a throw-away self-signed CA for tests.
func mustSelfSignedCA(t *testing.T, cn string) *x509.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// mustEncodeKeyedP12 wraps leaf + key (+ optional chain) into a PKCS#12
// file the test can load via loadSource.
func mustEncodeKeyedP12(t *testing.T, leaf *x509.Certificate, key *rsa.PrivateKey, chain []*x509.Certificate, pw string) []byte {
	t.Helper()
	out, err := pkcs12.Modern2023.WithRand(rand.Reader).Encode(key, leaf, chain, pw)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// mustEncodeTrustStoreP12 wraps the given CA certs into a keyless
// PKCS#12 truststore the test can load.
func mustEncodeTrustStoreP12(t *testing.T, cas []*x509.Certificate, pw string) []byte {
	t.Helper()
	entries := make([]pkcs12.TrustStoreEntry, len(cas))
	for i, c := range cas {
		entries[i] = pkcs12.TrustStoreEntry{Cert: c}
	}
	out, err := pkcs12.Modern2023.WithRand(rand.Reader).EncodeTrustStoreEntries(entries, pw)
	if err != nil {
		t.Fatal(err)
	}
	return out
}
