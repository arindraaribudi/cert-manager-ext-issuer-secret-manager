// Package awscert fetches issued certs from AWS Certificate Manager.
// ponytail: ExportCertificate returns one base64-encoded PEM blob containing
// cert + chain + (encrypted) private key — we split and (if needed)
// decrypt locally. Mirror reference repo's interface-driven design so
// fakes slot in for tests without touching the SDK.
package awscert

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/acm"
	"github.com/youmark/pkcs8"
)

// acmapi is the subset of *acm.Client used by Client. Defining as an
// interface lets tests substitute a fake without touching the SDK.
type acmapi interface {
	ExportCertificate(ctx context.Context, in *acm.ExportCertificateInput, opts ...func(*acm.Options)) (*acm.ExportCertificateOutput, error)
}

// Client wraps acmapi to download issued cert material.
type Client struct {
	api acmapi
}

// New returns a Client wrapping the given acmapi.
func New(api acmapi) *Client { return &Client{api: api} }

// Export downloads cert+chain+(encrypted)key for arn. Returns raw PEM bytes.
// ponytail: ACM's ExportCertificate response.Certificate is already a
// base64-encoded PEM blob (per AWS docs). We decode and return the raw
// PEM bytes; SplitPEM/DecryptPKCS8 handle the rest.
func (c *Client) Export(ctx context.Context, arn, passphrase string) ([]byte, error) {
	out, err := c.api.ExportCertificate(ctx, &acm.ExportCertificateInput{
		CertificateArn: &arn,
		Passphrase:     []byte(passphrase),
	})
	if err != nil {
		return nil, fmt.Errorf("acm: export: %w", err)
	}
	if out == nil || out.Certificate == nil {
		return nil, errors.New("acm: empty response")
	}
	raw, err := base64.StdEncoding.DecodeString(*out.Certificate)
	if err != nil {
		return nil, fmt.Errorf("acm: base64 decode: %w", err)
	}
	return raw, nil
}

// SplitPEM extracts (certChain, encryptedKey) from a single PEM blob.
// If no encrypted key block is present (public cert), key is empty.
func SplitPEM(blob []byte) (cert []byte, key []byte, err error) {
	rest := blob
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		switch {
		case strings.HasSuffix(block.Type, "CERTIFICATE"):
			cert = append(cert, pem.EncodeToMemory(block)...)
		case strings.Contains(block.Type, "PRIVATE KEY"):
			key = pem.EncodeToMemory(block)
		}
	}
	if len(cert) == 0 {
		return nil, nil, errors.New("awscert: no certificate block found in PEM")
	}
	return cert, key, nil
}

func ptr(s string) *string { return &s }

// DecryptPKCS8 decrypts an encrypted PKCS8 PEM block and re-encodes as
// PKCS8 unencrypted PEM. Used for ACM private-key export (the `passphrase`
// Secret key gates this — leave it empty for public certs).
func DecryptPKCS8(encryptedPEM []byte, passphrase string) ([]byte, error) {
	block, _ := pem.Decode(encryptedPEM)
	if block == nil {
		return nil, errors.New("awscert: no PEM block in encrypted key")
	}
	key, err := pkcs8.ParsePKCS8PrivateKey(block.Bytes, []byte(passphrase))
	if err != nil {
		return nil, fmt.Errorf("awscert: pkcs8 decrypt: %w", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("awscert: re-encode pkcs8: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}