package tencentcert

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/pem"
	"io"
	"testing"

	tccommon "github.com/tencentcloud/tencentcloud-sdk-go-intl-en/tencentcloud/common"
	sslapi "github.com/tencentcloud/tencentcloud-sdk-go-intl-en/tencentcloud/ssl/v20191205"
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

// TestExtractFromZIP_IgnoresTomcatKeystore reproduces the real incident: a
// Tencent "all formats" zip includes a Tomcat-format binary keystore file
// (name contains "key" as a substring of "keystore"). The old classifier
// matched on strings.Contains(name, "key") and bucketed that binary data
// as the private key, corrupting tls.key downstream.
func TestExtractFromZIP_IgnoresTomcatKeystore(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	files := map[string]string{
		"Apache/cert.crt":              "-----BEGIN CERTIFICATE-----\nLEAF\n-----END CERTIFICATE-----\n",
		"Apache/chain.crt":             "-----BEGIN CERTIFICATE-----\nCHAIN\n-----END CERTIFICATE-----\n",
		"Apache/key.key":               "-----BEGIN RSA PRIVATE KEY-----[REDACTED:Private key block]\n",
		"Tomcat/domain.keystore":       "\x00\x01BINARYJKSDATA-NOT-PEM",
		"Tomcat/keystore_password.txt": "hunter2",
	}
	for name, body := range files {
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
	if !bytes.HasPrefix(ex.PrivateKey, []byte("-----BEGIN RSA PRIVATE KEY-----")) {
		t.Fatalf("PrivateKey contaminated with non-PEM data: %q", ex.PrivateKey)
	}
	if bytes.Contains(ex.PrivateKey, []byte("BINARYJKSDATA")) {
		t.Fatal("PrivateKey contains Tomcat keystore binary bytes")
	}
}

// TestExtractFromZIP_MashedBlockSurvives reproduces the real incident:
// Tencent's Apache/1_root_bundle.crt ships without a trailing newline.
// Concatenating zip entries with a raw append() mashes its
// "-----END CERTIFICATE-----" directly against the next entry's
// "-----BEGIN CERTIFICATE-----", which makes pem.Decode's scan bail out
// early and silently drop every block after the mash point — including
// ones already correctly parsed earlier in the buffer.
func TestExtractFromZIP_MashedBlockSurvives(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	// Explicit order (not a map) so file 1 is guaranteed to precede file 2:
	// zip.NewReader iterates r.File in the order entries were written.
	type entry struct{ name, body string }
	for _, e := range []entry{
		{"cert.crt", "-----BEGIN CERTIFICATE-----\nLEAF\n-----END CERTIFICATE-----\n"},
		{"chain1.crt", "-----BEGIN CERTIFICATE-----\nCHAINAAA\n-----END CERTIFICATE-----"}, // no trailing newline
		{"chain2.crt", "-----BEGIN CERTIFICATE-----\nCHAINBBB\n-----END CERTIFICATE-----\n"},
		{"key.pem", "-----BEGIN RSA PRIVATE KEY-----\nKEY\n-----END RSA PRIVATE KEY-----\n"},
	} {
		w, err := zw.Create(e.name)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.WriteString(w, e.body)
	}
	_ = zw.Close()

	ex, err := ExtractFromZIP(buf.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	rest := ex.Chain
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		n++
	}
	if n != 2 {
		t.Fatalf("ExtractFromZIP: want 2 chain blocks (missing trailing newline must not drop the mashed-together block), got %d; chain=%q", n, ex.Chain)
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
