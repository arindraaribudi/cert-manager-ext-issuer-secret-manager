package controller

import (
	"crypto/sha256"
	"encoding/json"
	"encoding/pem"
	"fmt"

	api "github.com/arindraaribudi/cert-manager-ext-issuer-secret-manager/api/v1alpha1"
	"github.com/arindraaribudi/cert-manager-ext-issuer-secret-manager/internal/provider"
)

// extracted is what comes back from Extract. Alias of provider.Certificate
// kept local so the test file doesn't need to import the provider package.
type extracted = provider.Certificate

// Extract parses a JSON byte payload using the configured key names and
// returns the three PEM fields. Returns an error naming the missing field
// so callers can set Ready=False/InvalidPayload.
func Extract(payload []byte, keys api.PayloadKeys) (*extracted, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(payload, &raw); err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}

	certKey := keys.CertificateOrDefault()
	keyKey := keys.PrivateKeyOrDefault()
	chainKey := keys.CertificateChainOrDefault()

	certRaw, ok := raw[certKey]
	if !ok || len(certRaw) == 0 || string(certRaw) == `""` {
		return nil, fmt.Errorf("missing field %q", certKey)
	}
	keyRaw, ok := raw[keyKey]
	if !ok || len(keyRaw) == 0 || string(keyRaw) == `""` {
		return nil, fmt.Errorf("missing field %q", keyKey)
	}
	out := &extracted{Certificate: normalizePEM(mustUnquote(certRaw)), PrivateKey: normalizePEM(mustUnquote(keyRaw))}
	if chainRaw, ok := raw[chainKey]; ok && len(chainRaw) > 0 && string(chainRaw) != `""` {
		out.Chain = normalizePEM(mustUnquote(chainRaw))
	}
	return out, nil
}

func mustUnquote(raw json.RawMessage) []byte {
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return raw
	}
	return []byte(s)
}

// normalizePEM decodes every PEM block in raw, drops duplicates by DER
// SHA-256, and re-emits the surviving blocks with a single trailing
// newline. Trailing non-PEM bytes are discarded.
//
// ponytail: upstream providers occasionally concatenate the same block
// several times (rotation cycles) or mash blocks without newlines
// (`...END-----...BEGIN...`). Without this guard every consumer of the
// resulting Secret (cert-manager, nginx-ingress, JKS readers) sees a
// malformed tls.crt/tls.key. Fixing it at the Extract boundary keeps
// the providers blissfully unaware.
func normalizePEM(raw []byte) []byte {
	if len(raw) == 0 {
		return raw
	}
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
