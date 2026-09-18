// Package tencentcert fetches issued certs from Tencent Cloud SSL.
// ponytail: SSL API is a download ZIP with leaf/chain/key files — extract
// in memory, no separate fetch URL like the original SDK.
package tencentcert

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"

	sslapi "github.com/tencentcloud/tencentcloud-sdk-go-intl-en/tencentcloud/ssl/v20191205"
)

// ExportedParts is the result of extracting a Tencent SSL ZIP.
type ExportedParts struct {
	Leaf       []byte
	Chain      []byte
	PrivateKey []byte
}

// sslAPI is the subset of *ssl.Client used by SSLClient.
type sslAPI interface {
	DownloadCertificateWithContext(ctx context.Context, req *sslapi.DownloadCertificateRequest) (*sslapi.DownloadCertificateResponse, error)
}

// SSLClient wraps sslAPI. The reconcile layer talks to this interface,
// not the SDK struct directly — keeps the controller testable.
type SSLClient struct {
	api sslAPI
}

// New returns a Client wrapping the given sslAPI.
func New(api sslAPI) *SSLClient { return &SSLClient{api: api} }

// ExtractFromZIP opens a Tencent SSL download ZIP in memory and returns
// the cert leaf, intermediate chain, and private key files. ponytail: the
// SDK returns the ZIP as base64 in the response body, so we only need
// base64-decode here and let ExtractFromZIP handle the rest.
func ExtractFromZIP(z []byte) (*ExportedParts, error) {
	r, err := zip.NewReader(bytes.NewReader(z), int64(len(z)))
	if err != nil {
		return nil, fmt.Errorf("tencentcert: open zip: %w", err)
	}
	out := &ExportedParts{}
	for _, f := range r.File {
		rc, err := f.Open()
		if err != nil {
			return nil, fmt.Errorf("tencentcert: open %s: %w", f.Name, err)
		}
		data, err := io.ReadAll(rc)
		_ = rc.Close()
		if err != nil {
			return nil, err
		}
		lower := strings.ToLower(f.Name)
		switch {
		case strings.Contains(lower, "chain") || strings.Contains(lower, "intermediate"):
			out.Chain = append(out.Chain, data...)
		case strings.Contains(lower, "key"):
			out.PrivateKey = append(out.PrivateKey, data...)
		default:
			out.Leaf = append(out.Leaf, data...)
		}
	}
	if len(out.Leaf) == 0 || len(out.PrivateKey) == 0 {
		return nil, errors.New("tencentcert: missing leaf or key in zip")
	}
	return out, nil
}

// AssembleTLS concatenates leaf + chain for the tls.crt field.
func AssembleTLS(leaf, chain []byte) []byte {
	return append(append([]byte{}, leaf...), chain...)
}

// Download fetches and returns the (cert, chain, key) for id.
func (c *SSLClient) Download(ctx context.Context, id string) (*ExportedParts, error) {
	req := sslapi.NewDownloadCertificateRequest()
	req.CertificateId = &id
	resp, err := c.api.DownloadCertificateWithContext(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("tencentcert: download: %w", err)
	}
	if resp == nil || resp.Response == nil || resp.Response.Content == nil {
		return nil, errors.New("tencentcert: empty response")
	}
	zipBytes, err := base64.StdEncoding.DecodeString(*resp.Response.Content)
	if err != nil {
		return nil, fmt.Errorf("tencentcert: base64 decode: %w", err)
	}
	return ExtractFromZIP(zipBytes)
}