package awscert

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/acm"
)

// stubACM implements acmapi for tests.
type stubACM struct {
	exportOut *acm.ExportCertificateOutput
	exportErr error
}

func (s stubACM) ExportCertificate(_ context.Context, _ *acm.ExportCertificateInput, _ ...func(*acm.Options)) (*acm.ExportCertificateOutput, error) {
	return s.exportOut, s.exportErr
}

func TestSplitPEM_PublicOnly(t *testing.T) {
	// ACM public cert: cert+chain, no encrypted key block
	pem := "-----BEGIN CERTIFICATE-----\nMIIBAAIBADANBgkqhkiG9w0BAQEFAASAAkIB\n-----END CERTIFICATE-----\n" +
		"-----BEGIN CERTIFICATE-----\nMIICCjCCAbCgAwIBAgIBADANBgkqhkiG9w0BAQQF\n-----END CERTIFICATE-----\n"
	cert, key, err := SplitPEM([]byte(pem))
	if err != nil {
		t.Fatal(err)
	}
	if len(cert) == 0 || len(key) != 0 {
		t.Errorf("public cert: want non-empty cert and empty key, got cert=%d key=%d", len(cert), len(key))
	}
}

func TestExport_DecodesBase64AndReturnsRawPEM(t *testing.T) {
	// ACM's ExportCertificate returns base64-encoded PEM, matching real AWS
	// behavior. The stub mirrors that wire format.
	pemPlain := "-----BEGIN CERTIFICATE-----\nABC\n-----END CERTIFICATE-----\n"
	s := stubACM{exportOut: &acm.ExportCertificateOutput{
		Certificate: ptr(base64.StdEncoding.EncodeToString([]byte(pemPlain))),
	}}
	got, err := New(s).Export(context.Background(), "arn:aws:acm:...", "")
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	if string(got) != pemPlain {
		t.Errorf("want %q, got %q", pemPlain, got)
	}
}

// Fixture: openssl pkcs8 -topk8 -v2 aes-256-cbc -in /tmp/k.pem -passin pass:testpass -out /tmp/k8.pem -passout pass:testpass
// ponytail: youmark/pkcs8 only supports PBES2 (PKCS#5 v2), so the openssl
// command MUST use -v2 aes-256-cbc — the default is PBES1 and will fail
// decrypt with "only PBES2 supported".
const encryptedPKCS8Fixture = `-----BEGIN ENCRYPTED PRIVATE KEY-----
MIIFHzBJBgkqhkiG9w0BBQ0wPDAbBgkqhkiG9w0BBQwwDgQI5Kd39J0e/IICAggA
MB0GCWCGSAFlAwQBKgQQKLNJCai6MzrmGfBP5OCnFQSCBND8/FqQL9aiz1Kb9ftY
uuyGkr+sj2oIjgT+gZWuqikEm13Fz8ZdPUdZIzyCuO+RD0FJmDWfKW1ioxlPTNK1
ThpFnfJj6e/GOZB4TJnBlkGlu/bkeJbTcD0ThQYs5f6VPEprv9efEr2gY3dVWCex
mnMDwa9X1738Dd/C3nvIT975RMWYfZnxoYY8isaRkx/c3WHIsFifFjQ8ecWR48En
uIHmzZEPR1fmU2aZc/HAdOzQ3pJxIS5GMCJgjH3G121BhN+sodvT7sfx7Yhssyb7
ik9nftDx9O68fnRIvJs10WXjW5jN26N5djgEm20yCOLBcK/ZzWMJ2ZGLexQgoBJH
tyPKifcbpkDBxbptTJdsWXqeJgsCDHCVGIFXLDPdxN5YmLKAuu2qeIuZEXSG1kbZ
Db0072TquU7ts4KPHcZbFJXW5FjFYOiV5ffYFAYx0dsMDuH4rI6qFEgcHUXV0dsb
PTrI+R46QLLhEk2cL3cTryWyOXn0CdRTSwxg/Fog4C1SFmtF4HDzMpy1nRAu5YqS
MLnY2j1CBdVZmIq3VPlrgDvuJPaPRZau2liKBkR1i4HrDR1Iy+jcgNXt7zACt8fQ
Ux8SQp06sJtmjkL54D/SfYUsMdmRPTX/6VQZ+PW97UbvUEXmAf3ICiW35/DxmMEb
pNFOsuRlIuQQAy7Lj0Z0lLczlgnpzb5YJi8u5k8v4Dvzv7hYjyUErGNgliLQDozY
/xkhEAvWsBbDsHyNeesVU8LmRzXYCm7T9k6kw7nUSWDmKcPWR6FgLxTCRJsKGBn8
gQyi9phCNgPPFe3Ah9nvG+VIp7X0bnnhhmaUp3Qqtd5d4VQ0SexocLt6b/xk15XN
B46N9dV/pI9uwPYuy6o14JYYt3kliWVimmqp+oHg15ouJQUGJxC+28YcVDPyhFUU
eO0qohQ5xUryRWxNqDajE4zR3QzAgZenBGsAVAEC6v6uQjPwBvvmW1/fELu2Xcqv
5PPPgGGsZLGtP/RaQ6C1xWjazX/LqkiU6OY/nEFnoCz6nbJEzF/8XFaKPfjKZNKT
BklSINNn/kZxPsbq/Csa1F9G/vS9xljS8S9a4y6harNRSD0DEFZSmwP716wX3HjK
EJDdcJDhipO9UMZdG79DKRJAJloNuduXsVdNO2GQDXs+ZPFfxeG8xrY1hiGVMEZR
c16ojRmWvntp0V84mz1YR7hfzkPhuZxZZZiEB6XGPtQd1adQMpvYgzu3xkqOrhip
oDrx6+pqXH5SF88Tem3SIV4uoVW74nuysHXzL6pnC+yXLp2vrf/qxgGIiH0nWRCG
2xsg2cysouD66O2dPJbkNEjhRjXAD0CNWVvoQdVm+jKiW76BV6si28K7OzKyF/Ur
IRC11W4XXFAh4zJxmZzYDV9gET9gXwneNqd8cofd0Tt1ZucuvHags/u3cINk0Iud
6uB/PMEqGHDBdw7TWL4G8HqLOAnRxceTbSFV9AYjYX6IBuYonEqc0Afv3F77wb3z
1mxxdi6NSEebyWhxaP6Yf2zYwqgpgW4mRradA9pwfEK+hIjE0ot3ywX4gp1+h2MT
w1Iq3a2DtoZAf89XZ/3zR43j0iU8++lStu4dZVh2x7p7+5Rs/zShVIvPxl+XJlYW
Gz3CrPxOazA/WDfA7Zv0waajxQ==
-----END ENCRYPTED PRIVATE KEY-----
`

func TestDecryptPKCS8_RoundTrip(t *testing.T) {
	key, err := DecryptPKCS8([]byte(encryptedPKCS8Fixture), "testpass")
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if len(key) == 0 {
		t.Fatal("empty key")
	}
	if !strings.Contains(string(key), "BEGIN PRIVATE KEY") {
		t.Errorf("expected unencrypted PKCS8 PEM, got %q", key)
	}
	if strings.Contains(string(key), "ENCRYPTED") {
		t.Errorf("result still encrypted, got %q", key)
	}
}

func TestDecryptPKCS8_WrongPassphrase(t *testing.T) {
	if _, err := DecryptPKCS8([]byte(encryptedPKCS8Fixture), "wrongpass"); err == nil {
		t.Error("want error on wrong passphrase")
	}
}

