package controller

import (
	"encoding/pem"
	"strings"
	"testing"

	"github.com/arindraaribudi/cert-manager-ext-issuer-secret-manager/api/v1alpha1"
)

func TestExtract(t *testing.T) {
	cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("MIIB")})
	key := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("MIIE")})
	chain := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("MIIC")})

	cases := []struct {
		name    string
		json    string
		keys    v1alpha1.PayloadKeys
		want    *extracted
		wantErr bool
	}{
		{
			name: "all fields present",
			json: `{"certificate":"` + jsonEscape(string(cert)) + `","private_key":"` + jsonEscape(string(key)) + `","certificate_chain":"` + jsonEscape(string(chain)) + `"}`,
			keys: v1alpha1.PayloadKeys{},
			want: &extracted{Certificate: cert, PrivateKey: key, Chain: chain},
		},
		{
			name: "no chain",
			json: `{"certificate":"` + jsonEscape(string(cert)) + `","private_key":"` + jsonEscape(string(key)) + `"}`,
			keys: v1alpha1.PayloadKeys{},
			want: &extracted{Certificate: cert, PrivateKey: key, Chain: nil},
		},
		{
			name: "custom keys",
			json: `{"c":"` + jsonEscape(string(cert)) + `","k":"` + jsonEscape(string(key)) + `"}`,
			keys: v1alpha1.PayloadKeys{Certificate: "c", PrivateKey: "k"},
			want: &extracted{Certificate: cert, PrivateKey: key, Chain: nil},
		},
		{
			name: "duplicate private key blocks + trailing junk",
			// Real symptom observed in production: provider wrote the
			// same PRIVATE KEY block three times followed by an
			// arbitrary tail. Extract must collapse to a single block.
			json: `{"certificate":"` + jsonEscape(string(cert)) + `","private_key":"` +
				jsonEscape(string(key)) +
				jsonEscape(string(key)) +
				jsonEscape(string(key)) +
				`2rlgm2s58c2rlgm2s58c"}`,
			keys: v1alpha1.PayloadKeys{},
			want: &extracted{Certificate: cert, PrivateKey: key, Chain: nil},
		},
		{
			name: "certificates glued without newlines",
			// Same root cause: provider smashed three CERT blocks together
			// (`...END-----...BEGIN...`). Decode-and-re-encode fixes it.
			json: `{"certificate":"` + jsonEscape(strings.Repeat(string(cert), 3)) + `","private_key":"` + jsonEscape(string(key)) + `"}`,
			keys: v1alpha1.PayloadKeys{},
			want: &extracted{Certificate: cert, PrivateKey: key, Chain: nil},
		},
		{
			name: "certificates truly mashed with no newline at all",
			// The wire symptom: "-----END CERTIFICATE----------BEGIN
			// CERTIFICATE-----" on one line, zero bytes between them.
			// pem.Decode aborts entirely on this (returns a nil block on
			// the first pass), so NormalizePEM must split the glue before
			// decoding or the mash ships into the Secret untouched.
			json: `{"certificate":"` + jsonEscape(strings.Repeat(strings.TrimSuffix(string(cert), "\n"), 3)+"\n") + `","private_key":"` + jsonEscape(string(key)) + `"}`,
			keys: v1alpha1.PayloadKeys{},
			want: &extracted{Certificate: cert, PrivateKey: key, Chain: nil},
		},
		{
			name:    "missing certificate",
			json:    `{"private_key":"` + jsonEscape(string(key)) + `"}`,
			keys:    v1alpha1.PayloadKeys{},
			wantErr: true,
		},
		{
			name:    "missing private key",
			json:    `{"certificate":"` + jsonEscape(string(cert)) + `"}`,
			keys:    v1alpha1.PayloadKeys{},
			wantErr: true,
		},
		{
			name:    "invalid json",
			json:    `not json`,
			keys:    v1alpha1.PayloadKeys{},
			wantErr: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Extract([]byte(tc.json), tc.keys)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if string(got.Certificate) != string(tc.want.Certificate) {
				t.Errorf("certificate mismatch:\n got %q\nwant %q", got.Certificate, tc.want.Certificate)
			}
			if string(got.PrivateKey) != string(tc.want.PrivateKey) {
				t.Errorf("private key mismatch:\n got %q\nwant %q", got.PrivateKey, tc.want.PrivateKey)
			}
			if string(got.Chain) != string(tc.want.Chain) {
				t.Errorf("chain mismatch:\n got %q\nwant %q", got.Chain, tc.want.Chain)
			}
		})
	}
}

// jsonEscape escapes the few characters a JSON string literal needs so the
// test inputs can concatenate raw PEM bytes without template gymnastics.
func jsonEscape(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch r {
		case '"', '\\':
			b.WriteByte('\\')
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}
