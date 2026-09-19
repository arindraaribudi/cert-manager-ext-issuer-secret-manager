// Package keystore converts TLS material (PEM cert + key + chain) into
// JKS and PKCS#12 keystores suitable for JVM/Python consumers. The
// resulting artifacts are written into the same kubernetes.io/tls Secret
// cert-manager already manages; this package only adds auxiliary keys,
// it never replaces the TLS payload.
package keystore

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	ks "github.com/pavlo-v-chernykh/keystore-go/v4"
	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

const passwordBytes = 24

// reuseOrGeneratePassword returns a stable base64-encoded password.
// When existingSecret carries a keystore.password AND its tls.crt and
// tls.key match the inputs byte-for-byte, the existing password is
// reused (stable across reconciles). Otherwise a fresh 24-byte random
// password is generated and base64-encoded. The base64 form is what
// we store in Secret.Data["keystore.password"].
func reuseOrGeneratePassword(certPEM, keyPEM []byte, existingSecret *corev1.Secret) ([]byte, error) {
	if existingSecret != nil {
		if pw, ok := existingSecret.Data["keystore.password"]; ok && len(pw) > 0 {
			if bytesEqual(existingSecret.Data["tls.crt"], certPEM) &&
				bytesEqual(existingSecret.Data["tls.key"], keyPEM) {
				return pw, nil
			}
		}
	}
	raw := make([]byte, passwordBytes)
	if _, err := rand.Read(raw); err != nil {
		return nil, fmt.Errorf("keystore: rand.Read: %w", err)
	}
	out := make([]byte, base64.StdEncoding.EncodedLen(len(raw)))
	base64.StdEncoding.Encode(out, raw)
	return out, nil
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// buildJKS creates a JKS keystore with one PrivateKeyEntry (alias = leaf
// cert CN, with cert chain) plus zero or more TrustedCertificateEntry
// values for the CA chain. chainPEM may contain multiple
// "-----BEGIN CERTIFICATE-----" blocks. password is the keystore password
// (same bytes callers persist as keystore.password Secret key).
func buildJKS(certPEM, keyPEM, chainPEM, password []byte) ([]byte, error) {
	leafBlock, _ := pem.Decode(certPEM)
	if leafBlock == nil {
		return nil, fmt.Errorf("keystore: leaf cert PEM malformed")
	}
	leaf, err := x509.ParseCertificate(leafBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("keystore: parse leaf cert: %w", err)
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, fmt.Errorf("keystore: private key PEM malformed")
	}
	// keystore-go expects PKCS#8 DER (the README is explicit).
	if keyBlock.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("keystore: private key must be PKCS#8 (got %q), not PKCS#1", keyBlock.Type)
	}

	alias := aliasFor(leaf)
	store := ks.New()
	now := time.Now().UTC()

	chainCerts, err := parseChainDER(chainPEM)
	if err != nil {
		return nil, err
	}
	chainKS := make([]ks.Certificate, 0, 1+len(chainCerts))
	chainKS = append(chainKS, ks.Certificate{Type: "X.509", Content: leaf.Raw})
	for _, c := range chainCerts {
		chainKS = append(chainKS, ks.Certificate{Type: "X.509", Content: c.Raw})
	}
	if err := store.SetPrivateKeyEntry(alias, ks.PrivateKeyEntry{
		CreationTime:     now,
		PrivateKey:       keyBlock.Bytes,
		CertificateChain: chainKS,
	}, password); err != nil {
		return nil, fmt.Errorf("keystore: set private key entry: %w", err)
	}

	for i, c := range chainCerts {
		if err := store.SetTrustedCertificateEntry(
			fmt.Sprintf("chain-%d", i),
			ks.TrustedCertificateEntry{CreationTime: now, Certificate: ks.Certificate{Type: "X.509", Content: c.Raw}},
		); err != nil {
			return nil, fmt.Errorf("keystore: set chain entry %d: %w", i, err)
		}
	}

	var buf bytes.Buffer
	if err := store.Store(&buf, password); err != nil {
		return nil, fmt.Errorf("keystore: store JKS: %w", err)
	}
	return buf.Bytes(), nil
}

// buildPKCS12 creates a PKCS#12 keystore with one leaf cert + private
// key plus zero or more CA chain certs. password is the keystore
// password (same bytes callers persist as keystore.password Secret key).
// Uses LegacyRC2 for maximum compatibility with legacy Java/OpenSSL
// consumers — Modern would fail on Java 8 / older Tomcat.
func buildPKCS12(certPEM, keyPEM, chainPEM, password []byte) ([]byte, error) {
	leafBlock, _ := pem.Decode(certPEM)
	if leafBlock == nil {
		return nil, fmt.Errorf("keystore: leaf cert PEM malformed")
	}
	leaf, err := x509.ParseCertificate(leafBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("keystore: parse leaf cert: %w", err)
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, fmt.Errorf("keystore: private key PEM malformed")
	}
	priv, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("keystore: parse PKCS8 key: %w", err)
	}

	chainCerts, err := parseChainDER(chainPEM)
	if err != nil {
		return nil, err
	}
	caPtrs := make([]*x509.Certificate, len(chainCerts))
	for i := range chainCerts {
		caPtrs[i] = &chainCerts[i]
	}

	return pkcs12.LegacyRC2.WithRand(rand.Reader).Encode(priv, leaf, caPtrs, string(password))
}

// aliasFor returns the keystore alias for the leaf certificate.
// Order: Subject.CN → first DNS name → literal "leaf".
func aliasFor(leaf *x509.Certificate) string {
	if cn := leaf.Subject.CommonName; cn != "" {
		return cn
	}
	if len(leaf.DNSNames) > 0 {
		return leaf.DNSNames[0]
	}
	return "leaf"
}

// parseChainDER splits chainPEM into one or more *x509.Certificate
// values. Malformed blocks are skipped (logged via error return when
// no valid certs found). Empty input returns an empty slice.
func parseChainDER(chainPEM []byte) ([]x509.Certificate, error) {
	if len(chainPEM) == 0 {
		return nil, nil
	}
	var out []x509.Certificate
	rest := chainPEM
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			// Skip malformed blocks — callers already have a leaf cert
			// in hand and a partial chain beats no chain.
			continue
		}
		out = append(out, *c)
	}
	if out == nil && len(chainPEM) > 0 {
		return nil, fmt.Errorf("keystore: chain PEM had blocks but none parsed as certificates")
	}
	return out, nil
}

// SplitLeafAndChain separates the first CERTIFICATE block (leaf) from
// any subsequent CERTIFICATE blocks (intermediate CAs) in a PEM bundle.
// Used by callers whose upstream delivers leaf+chain concatenated.
func SplitLeafAndChain(bundle []byte) (leaf, chain []byte) {
	rest := bundle
	first := true
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		encoded := pem.EncodeToMemory(block)
		if first {
			leaf = encoded
			first = false
			continue
		}
		chain = append(chain, encoded...)
	}
	return leaf, chain
}

// Build converts (certPEM, keyPEM, chainPEM) into JKS + PKCS12 keystores
// and returns the artifacts ready to drop into a corev1.Secret's Data
// map under the keys "keystore.jks", "keystore.p12", "keystore.password".
//
// existingSecret is the currently-deployed Secret (may be nil for first
// reconcile); if it carries keystore.password AND its tls.crt/tls.key
// match the inputs byte-for-byte, the same password is reused —
// stable across reconciles.
//
// Return values:
//   - jks, p12, password: bytes ready for Secret.Data
//   - skipped: true when keyPEM is empty; outputs are nil in that case
//   - err: non-nil only for unrecoverable failures (malformed PEM,
//     keystore library error); empty keyPEM is NOT an error
func Build(certPEM, keyPEM, chainPEM []byte, existingSecret *corev1.Secret) (jks, p12, password []byte, skipped bool, err error) {
	if len(keyPEM) == 0 {
		return nil, nil, nil, true, nil
	}

	password, err = reuseOrGeneratePassword(certPEM, keyPEM, existingSecret)
	if err != nil {
		return nil, nil, nil, false, fmt.Errorf("keystore: password: %w", err)
	}

	jks, err = buildJKS(certPEM, keyPEM, chainPEM, password)
	if err != nil {
		return nil, nil, nil, false, err
	}

	p12, err = buildPKCS12(certPEM, keyPEM, chainPEM, password)
	if err != nil {
		return nil, nil, nil, false, err
	}

	return jks, p12, password, false, nil
}

// ParseJKSForTest parses a JKS blob with the given password. Exported
// so cross-package tests can verify round-trips without depending on
// keystore-go directly.
func ParseJKSForTest(jks, password []byte) error {
	store := ks.New()
	return store.Load(bytes.NewReader(jks), password)
}