package controller

import (
	"testing"

	"github.com/arindraaribudi/cert-manager-ext-issuer-secret-manager/api/v1alpha1"
)

func TestExtract(t *testing.T) {
	cert := []byte("-----BEGIN CERTIFICATE-----MIIB-----END CERTIFICATE-----")
	key := []byte("-----BEGIN PRIVATE KEY-----MIIE-----END PRIVATE KEY-----")
	chain := []byte("-----BEGIN CERTIFICATE-----MIIC-----END CERTIFICATE-----")

	cases := []struct {
		name    string
		json    string
		keys    v1alpha1.PayloadKeys
		want    *extracted
		wantErr bool
	}{
		{
			name: "all fields present",
			json: `{"certificate":"` + string(cert) + `","private_key":"` + string(key) + `","certificate_chain":"` + string(chain) + `"}`,
			keys: v1alpha1.PayloadKeys{},
			want: &extracted{Certificate: cert, PrivateKey: key, Chain: chain},
		},
		{
			name: "no chain",
			json: `{"certificate":"` + string(cert) + `","private_key":"` + string(key) + `"}`,
			keys: v1alpha1.PayloadKeys{},
			want: &extracted{Certificate: cert, PrivateKey: key, Chain: nil},
		},
		{
			name: "custom keys",
			json: `{"c":"` + string(cert) + `","k":"` + string(key) + `"}`,
			keys: v1alpha1.PayloadKeys{Certificate: "c", PrivateKey: "k"},
			want: &extracted{Certificate: cert, PrivateKey: key, Chain: nil},
		},
		{
			name:    "missing certificate",
			json:    `{"private_key":"` + string(key) + `"}`,
			keys:    v1alpha1.PayloadKeys{},
			wantErr: true,
		},
		{
			name:    "missing private key",
			json:    `{"certificate":"` + string(cert) + `"}`,
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
				t.Errorf("certificate mismatch: got %q want %q", got.Certificate, tc.want.Certificate)
			}
			if string(got.PrivateKey) != string(tc.want.PrivateKey) {
				t.Errorf("private key mismatch")
			}
			if string(got.Chain) != string(tc.want.Chain) {
				t.Errorf("chain mismatch")
			}
		})
	}
}
