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
		lower := strings.ToLower(f.Name)
		// Tomcat/IIS format folders ship binary keystore + password
		// artifacts (xxx.keystore, xxx.jks, xxx.pfx, xxx.p12, xxx_password.txt)
		// alongside the PEM files. A loose "contains key" match (Tomcat's
		// "xxx.keystore" contains "key") used to bucket that binary data as
		// the private key, which then rode a NormalizePEM fallback straight
		// into the Secret's tls.key. Skip known-binary formats outright.
		if strings.HasSuffix(lower, ".jks") || strings.HasSuffix(lower, ".keystore") ||
			strings.HasSuffix(lower, ".pfx") || strings.HasSuffix(lower, ".p12") ||
			strings.HasSuffix(lower, ".txt") {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return nil, fmt.Errorf("tencentcert: open %s: %w", f.Name, err)
		}
		data, err := io.ReadAll(rc)
		_ = rc.Close()
		if err != nil {
			return nil, err
		}
		switch {
		case strings.Contains(lower, "chain") || strings.Contains(lower, "intermediate"):
			out.Chain = appendPEM(out.Chain, data)
		case strings.Contains(lower, "key"):
			out.PrivateKey = appendPEM(out.PrivateKey, data)
		default:
			out.Leaf = appendPEM(out.Leaf, data)
		}
	}
	if len(out.Leaf) == 0 || len(out.PrivateKey) == 0 {
		return nil, errors.New("tencentcert: missing leaf or key in zip")
	}
	return out, nil
}

// appendPEM appends data to dst, inserting a separating newline first when
// dst is non-empty and doesn't already end in one. Tencent zip entries
// aren't guaranteed to end with a trailing newline (e.g. Apache/1_root_
// bundle.crt); a raw append then mashes "...END CERTIFICATE----------BEGIN
// CERTIFICATE-----" together, which makes pem.Decode's block scan bail out
// early and silently drop every block after the mash point — including
// ones already correctly parsed earlier in the buffer.
func appendPEM(dst, data []byte) []byte {
	if len(dst) > 0 && dst[len(dst)-1] != '\n' {
		dst = append(dst, '\n')
	}
	return append(dst, data...)
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
