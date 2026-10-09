package controller

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"encoding/pem"
	"fmt"

	api "github.com/arindraaribudi/cert-manager-ext-issuer-secret-manager/api/v1alpha1"
	"github.com/arindraaribudi/cert-manager-ext-issuer-secret-manager/internal/keystore"
	"github.com/arindraaribudi/cert-manager-ext-issuer-secret-manager/internal/provider"
)

// extracted is what comes back from Extract. Alias of provider.Certificate
// kept local so the test file doesn't need to import the provider package.
type extracted = provider.Certificate

// Extract parses a JSON byte payload using the configured key names and
// returns the three PEM fields. Chain-only payloads (only certificate_chain
// set) are valid: the leaf is derived from chain[0] and the rest stays as
// the chain. An error names the missing field so callers can set
// Ready=False/InvalidPayload.
func Extract(payload []byte, keys api.PayloadKeys) (*extracted, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(payload, &raw); err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}

	certKey := keys.CertificateOrDefault()
	keyKey := keys.PrivateKeyOrDefault()
	chainKey := keys.CertificateChainOrDefault()

	certPEM := pemField(raw[certKey])
	keyPEM := pemField(raw[keyKey])
	chainPEM := pemField(raw[chainKey])

	if len(certPEM) == 0 && len(chainPEM) == 0 {
		return nil, fmt.Errorf("missing field %q (or %q)", certKey, chainKey)
	}
	if len(keyPEM) == 0 && len(chainPEM) == 0 {
		return nil, fmt.Errorf("missing field %q (or %q)", keyKey, chainKey)
	}
	// Chain-only source: derive leaf from chain[0], remainder stays as chain
	// so downstream splits (tls.crt, ca.crt, truststore.jks) work uniformly.
	if len(certPEM) == 0 {
		leaf, rest := keystore.SplitLeafAndChain(chainPEM)
		certPEM = leaf
		chainPEM = rest
	}
	return &extracted{Certificate: certPEM, PrivateKey: keyPEM, Chain: chainPEM}, nil
}

// pemField returns the PEM bytes for a JSON field, applying the same
// unwrap-and-normalize steps Extract always used. Missing / empty / `""`
// all collapse to nil.
func pemField(raw json.RawMessage) []byte {
	if len(raw) == 0 || string(raw) == `""` {
		return nil
	}
	return NormalizePEM(mustUnquote(raw))
}

func mustUnquote(raw json.RawMessage) []byte {
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return raw
	}
	return []byte(s)
}

// NormalizePEM decodes every PEM block in raw, drops duplicates by DER
// SHA-256, and re-emits the surviving blocks with a single trailing
// newline. Trailing non-PEM bytes are discarded.
//
// ponytail: upstream providers occasionally concatenate the same block
// several times (rotation cycles) or mash blocks without newlines
// (`...END-----...BEGIN...`). Without this guard every consumer of the
// resulting Secret (cert-manager, nginx-ingress, JKS readers) sees a
// malformed tls.crt/tls.key. Fixing it at the Extract boundary keeps
// the providers blissfully unaware.
func NormalizePEM(raw []byte) []byte {
	if len(raw) == 0 {
		return raw
	}
	// pem.Decode bails out (returns a nil block) the instant END and BEGIN
	// share one line with no newline between them, so a single mashed
	// boundary aborts the whole scan and the fallback below would ship the
	// mash straight into the Secret untouched. Split the glue before decoding.
	raw = bytes.ReplaceAll(raw, []byte("----------BEGIN"), []byte("-----\n-----BEGIN"))
	seen := make(map[[32]byte]bool, 4)
	var out []byte
	rest := raw
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		sum := sha256.Sum256(block.Bytes)
		if seen[sum] {
			continue
		}
		seen[sum] = true
		out = append(out, pem.EncodeToMemory(block)...)
	}
	if len(out) == 0 {
		// ponytail: no blocks found at all → return the original bytes
		// unchanged so a malformed payload surfaces as the original error
		// downstream instead of a silent empty Secret.
		return raw
	}
	return out
}
