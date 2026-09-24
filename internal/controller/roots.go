package controller

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
)

// knownRoots holds self-signed root CA certs CompleteChain is willing to
// append to a served chain when the top of the chain was issued by one of
// them. CAs normally don't ship the root in a download bundle — clients
// trust it natively — so this only matters when a consumer wants the full
// chain anyway.
// ponytail: single entry for now (covers Tencent's Thawte/DigiCert-issued
// certs); add more root PEMs here as other issuers come up.
var knownRoots = [][]byte{
	[]byte(`-----BEGIN CERTIFICATE-----
MIIDjjCCAnagAwIBAgIQAzrx5qcRqaC7KGSxHQn65TANBgkqhkiG9w0BAQsFADBh
MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3
d3cuZGlnaWNlcnQuY29tMSAwHgYDVQQDExdEaWdpQ2VydCBHbG9iYWwgUm9vdCBH
MjAeFw0xMzA4MDExMjAwMDBaFw0zODAxMTUxMjAwMDBaMGExCzAJBgNVBAYTAlVT
MRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5j
b20xIDAeBgNVBAMTF0RpZ2lDZXJ0IEdsb2JhbCBSb290IEcyMIIBIjANBgkqhkiG
9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuzfNNNx7a8myaJCtSnX/RrohCgiN9RlUyfuI
2/Ou8jqJkTx65qsGGmvPrC3oXgkkRLpimn7Wo6h+4FR1IAWsULecYxpsMNzaHxmx
1x7e/dfgy5SDN67sH0NO3Xss0r0upS/kqbitOtSZpLYl6ZtrAGCSYP9PIUkY92eQ
q2EGnI/yuum06ZIya7XzV+hdG82MHauVBJVJ8zUtluNJbd134/tJS7SsVQepj5Wz
tCO7TG1F8PapspUwtP1MVYwnSlcUfIKdzXOS0xZKBgyMUNGPHgm+F6HmIcr9g+UQ
vIOlCsRnKPZzFBQ9RnbDhxSJITRNrw9FDKZJobq7nMWxM4MphQIDAQABo0IwQDAP
BgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBhjAdBgNVHQ4EFgQUTiJUIBiV
5uNu5g/6+rkS7QYXjzkwDQYJKoZIhvcNAQELBQADggEBAGBnKJRvDkhj6zHd6mcY
1Yl9PMWLSn/pvtsrF9+wX3N3KjITOYFnQoQj8kVnNeyIv/iPsGEMNKSuIEyExtv4
NeF22d+mQrvHRAiGfzZ0JFrabA0UWTW98kndth/Jsw1HKj2ZL7tcu7XUIOGZX1NG
Fdtom/DzMNU+MeKNhJ7jitralj41E6Vf8PlwUHBHQRFXGU7Aj64GxJUTFy8bJZ91
8rGOmaFvE7FBcf6IKshPECBV1/MUReXgRPTqh5Uykw7+U0b6LJ3/iyK5S9kJRaTe
pLiaWN0bfVKfjllDiIGknibVb63dDcY3fe0Dkhvld1927jyNxF1WW6LZZm6zNTfl
MrY=
-----END CERTIFICATE-----
`),
}

// CompleteChain appends a known root CA cert after certPEM's last block if
// that block isn't already self-signed and a known root's signature
// verifies against it. No-op (returns certPEM unchanged) if certPEM is
// empty, unparseable, already ends in a self-signed cert, or no known root
// matches — never appends a root that doesn't actually verify.
func CompleteChain(certPEM []byte) []byte {
	return completeChain(certPEM, knownRoots)
}

func completeChain(certPEM []byte, roots [][]byte) []byte {
	top := lastCert(certPEM)
	if top == nil || bytes.Equal(top.RawIssuer, top.RawSubject) {
		return certPEM
	}
	for _, rootPEM := range roots {
		block, _ := pem.Decode(rootPEM)
		if block == nil {
			continue
		}
		root, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}
		if top.CheckSignatureFrom(root) == nil {
			return NormalizePEM(append(append([]byte{}, certPEM...), rootPEM...))
		}
	}
	return certPEM
}

// lastCert returns the last successfully parsed certificate in certPEM, or
// nil if none parse.
func lastCert(certPEM []byte) *x509.Certificate {
	var last *x509.Certificate
	rest := certPEM
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
			last = cert
		}
	}
	return last
}
