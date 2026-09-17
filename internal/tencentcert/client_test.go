package tencentcert

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/base64"
	"io"
	"testing"

	sslapi "github.com/tencentcloud/tencentcloud-sdk-go-intl-en/tencentcloud/ssl/v20191205"
	tccommon "github.com/tencentcloud/tencentcloud-sdk-go-intl-en/tencentcloud/common"
)

// stubSSL implements sslAPI for tests.
type stubSSL struct {
	downloadOut *sslapi.DownloadCertificateResponse
	downloadErr error
}

func (s stubSSL) DownloadCertificateWithContext(_ context.Context, _ *sslapi.DownloadCertificateRequest) (*sslapi.DownloadCertificateResponse, error) {
	return s.downloadOut, s.downloadErr
}

func TestExtractFromZIP(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, body := range map[string]string{
		"cert.crt":  "-----BEGIN CERTIFICATE-----\nLEAF\n-----END CERTIFICATE-----\n",
		"chain.crt": "-----BEGIN CERTIFICATE-----\nCHAIN\n-----END CERTIFICATE-----\n",
		"key.pem":   "-----BEGIN RSA PRIVATE KEY-----\nKEY\n-----END RSA PRIVATE KEY-----\n",
	} {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.WriteString(w, body)
	}
	_ = zw.Close()

	ex, err := ExtractFromZIP(buf.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if len(ex.Leaf) == 0 || len(ex.Chain) == 0 || len(ex.PrivateKey) == 0 {
		t.Errorf("missing parts: leaf=%d chain=%d key=%d", len(ex.Leaf), len(ex.Chain), len(ex.PrivateKey))
	}
}

func TestAssembleTLS(t *testing.T) {
	got := AssembleTLS([]byte("LEAF\n"), []byte("CHAIN\n"))
	if string(got) != "LEAF\nCHAIN\n" {
		t.Errorf("got %q", got)
	}
}

func TestDownload_DecodesBase64AndExtracts(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, body := range map[string]string{
		"cert.crt":  "-----BEGIN CERTIFICATE-----\nL\n-----END CERTIFICATE-----\n",
		"chain.crt": "-----BEGIN CERTIFICATE-----\nC\n-----END CERTIFICATE-----\n",
		"key.pem":   "-----BEGIN RSA PRIVATE KEY-----\nK\n-----END RSA PRIVATE KEY-----\n",
	} {
		w, _ := zw.Create(name)
		_, _ = io.WriteString(w, body)
	}
	_ = zw.Close()
	encoded := base64.StdEncoding.EncodeToString(buf.Bytes())

	content := encoded
	stub := stubSSL{downloadOut: &sslapi.DownloadCertificateResponse{
		Response: &sslapi.DownloadCertificateResponseParams{
			Content: &content,
		},
	}}

	cli := New(stub)
	parts, err := cli.Download(context.Background(), "AbCdEf")
	if err != nil {
		t.Fatal(err)
	}
	if len(parts.Leaf) == 0 {
		t.Error("empty leaf")
	}
}

// pin imports so unused-import errors don't bite
var (
	_ = tccommon.StringPtr
)