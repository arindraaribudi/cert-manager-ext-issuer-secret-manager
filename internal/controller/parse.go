package controller

import (
	"encoding/json"
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
	out := &extracted{Certificate: mustUnquote(certRaw), PrivateKey: mustUnquote(keyRaw)}
	if chainRaw, ok := raw[chainKey]; ok && len(chainRaw) > 0 && string(chainRaw) != `""` {
		out.Chain = mustUnquote(chainRaw)
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
