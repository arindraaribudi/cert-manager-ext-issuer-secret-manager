package controller

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"

	"github.com/arindraaribudi/cert-manager-ext-issuer-secret-manager/internal/keystore"
)

// VerifyChain checks that leafPEM is signed by the first chainPEM cert,
// which is signed by the second, and so on — a valid signing path from
// leaf to the end of the supplied chain. No system/root trust store is
// consulted; private/internal CAs are expected. No-op when chainPEM is
// empty — chain is optional upstream.
func VerifyChain(leafPEM, chainPEM []byte) error {
	if len(chainPEM) == 0 {
		return nil
	}
	leaf, err := parseLeadingCert(leafPEM)
	if err != nil {
		return fmt.Errorf("chain: leaf: %w", err)
	}
	var chainCerts []*x509.Certificate
	rest := chainPEM
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return fmt.Errorf("chain: parse intermediate %d: %w", len(chainCerts), err)
		}
		chainCerts = append(chainCerts, cert)
	}
	if len(chainCerts) == 0 {
		return fmt.Errorf("chain: no certificates parsed from chain PEM")
	}
	cur := leaf
	for i, next := range chainCerts {
		if err := cur.CheckSignatureFrom(next); err != nil {
			return fmt.Errorf("chain: link %d (%s -> %s): %w", i, cur.Subject, next.Subject, err)
		}
		cur = next
	}
	return nil
}

func parseLeadingCert(certPEM []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, fmt.Errorf("PEM malformed")
	}
	return x509.ParseCertificate(block.Bytes)
}

// countCerts returns how many PEM certificate blocks are present.
func countCerts(certPEM []byte) int {
	n := 0
	rest := certPEM
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			n++
		}
	}
	return n
}

// ChainComposition describes the certificate types present in certPEM as a
// pipe-joined list in canonical order (leaf, intermediate, root); the first
// parsed block is always the leaf, later blocks are "root" when
// self-signed (Issuer == Subject) or "intermediate" otherwise. Each type
// appears at most once regardless of how many certs of that type are
// present, and an absent type (e.g. no root shipped) is omitted rather
// than zero-valued.
func ChainComposition(certPEM []byte) string {
	var hasLeaf, hasIntermediate, hasRoot bool
	first := true
	rest := certPEM
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}
		switch {
		case first:
			hasLeaf = true
		case bytes.Equal(cert.RawIssuer, cert.RawSubject):
			hasRoot = true
		default:
			hasIntermediate = true
		}
		first = false
	}
	var parts []string
	if hasLeaf {
		parts = append(parts, "leaf")
	}
	if hasIntermediate {
		parts = append(parts, "intermediate")
	}
	if hasRoot {
		parts = append(parts, "root")
	}
	return strings.Join(parts, "|")
}

// parsePrivateKey PEM-decodes and parses keyPEM as PKCS8, PKCS1, or EC —
// whichever the block actually is.
func parsePrivateKey(keyPEM []byte) error {
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return fmt.Errorf("PEM malformed")
	}
	if _, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		return nil
	}
	if _, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return nil
	}
	if _, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return nil
	}
	return fmt.Errorf("unrecognized private key format")
}

// VerifySecretData re-parses what's about to be persisted: tls.crt must
// PEM-decode and x509-parse, tls.key (when present — some providers
// legitimately have no exportable private key) must PEM-decode and parse,
// and keystore.jks (if present) must load with keystore.password. Guards
// against a NormalizePEM/keystore bug or a mis-extracted provider zip
// silently shipping a broken Secret.
func VerifySecretData(data map[string][]byte) error {
	if _, err := parseLeadingCert(data["tls.crt"]); err != nil {
		return fmt.Errorf("verify: tls.crt: %w", err)
	}
	if key := data["tls.key"]; len(key) > 0 {
		if err := parsePrivateKey(key); err != nil {
			return fmt.Errorf("verify: tls.key: %w", err)
		}
	}
	if jks := data["keystore.jks"]; len(jks) > 0 {
		if err := keystore.ParseJKSForTest(jks, data["keystore.password"]); err != nil {
			return fmt.Errorf("verify: keystore.jks: %w", err)
		}
	}
	return nil
}
