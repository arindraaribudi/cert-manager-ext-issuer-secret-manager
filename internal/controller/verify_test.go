package controller

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

// genCert issues a cert signed by parent (self-signed when parent == tmpl).
func genCert(t *testing.T, cn string, isCA bool, parentTmpl *x509.Certificate, parentKey *ecdsa.PrivateKey) ([]byte, *x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  isCA,
	}
	signerTmpl, signerKey := tmpl, key
	if parentTmpl != nil {
		signerTmpl, signerKey = parentTmpl, parentKey
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signerTmpl, &key.PublicKey, signerKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return pemBytes, cert, key
}

// genKeyPEM PKCS8/PEM-encodes an ecdsa private key, e.g. one returned by genCert.
func genKeyPEM(t *testing.T, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

func TestVerifyChain_ValidTwoLink(t *testing.T) {
	rootPEM, rootCert, rootKey := genCert(t, "root", true, nil, nil)
	leafPEM, _, _ := genCert(t, "leaf", false, rootCert, rootKey)

	if err := VerifyChain(leafPEM, rootPEM); err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
}

func TestVerifyChain_EmptyChainIsNoop(t *testing.T) {
	leafPEM, _, _ := genCert(t, "leaf", false, nil, nil)
	if err := VerifyChain(leafPEM, nil); err != nil {
		t.Fatalf("VerifyChain with empty chain: %v", err)
	}
}

func TestVerifyChain_WrongIntermediateFails(t *testing.T) {
	// leaf signed by root1; chain supplied is an unrelated root2.
	_, root1Cert, root1Key := genCert(t, "root1", true, nil, nil)
	leafPEM, _, _ := genCert(t, "leaf", false, root1Cert, root1Key)
	root2PEM, _, _ := genCert(t, "root2", true, nil, nil)

	if err := VerifyChain(leafPEM, root2PEM); err == nil {
		t.Fatal("VerifyChain: want error for mismatched intermediate, got nil")
	}
}

func TestVerifySecretData_ValidCert(t *testing.T) {
	certPEM, _, key := genCert(t, "leaf", false, nil, nil)
	data := map[string][]byte{"tls.crt": certPEM, "tls.key": genKeyPEM(t, key)}
	if err := VerifySecretData(data); err != nil {
		t.Fatalf("VerifySecretData: %v", err)
	}
}

func TestVerifySecretData_CorruptCertFails(t *testing.T) {
	_, _, key := genCert(t, "leaf", false, nil, nil)
	data := map[string][]byte{"tls.crt": []byte("not a cert"), "tls.key": genKeyPEM(t, key)}
	if err := VerifySecretData(data); err == nil {
		t.Fatal("VerifySecretData: want error for corrupt tls.crt, got nil")
	}
}

func TestVerifySecretData_CorruptJKSFails(t *testing.T) {
	certPEM, _, key := genCert(t, "leaf", false, nil, nil)
	data := map[string][]byte{
		"tls.crt":      certPEM,
		"tls.key":      genKeyPEM(t, key),
		"keystore.jks": []byte("not a jks"),
	}
	if err := VerifySecretData(data); err == nil {
		t.Fatal("VerifySecretData: want error for corrupt keystore.jks, got nil")
	}
}

// TestVerifySecretData_CorruptKeyFails reproduces the real incident: a
// Tencent Tomcat-format zip's binary keystore file got misclassified as
// the PEM private key and rode NormalizePEM's "no PEM found, return raw
// unchanged" fallback straight into tls.key. cert-manager core then failed
// with "no PEM data was found in given input". Binary junk in tls.key must
// be caught here, before the Secret is written.
func TestVerifySecretData_CorruptKeyFails(t *testing.T) {
	certPEM, _, _ := genCert(t, "leaf", false, nil, nil)
	data := map[string][]byte{"tls.crt": certPEM, "tls.key": {0x00, 0x01, 0x02, 0x03, 'J', 'K', 'S'}}
	if err := VerifySecretData(data); err == nil {
		t.Fatal("VerifySecretData: want error for binary garbage tls.key, got nil")
	}
}

// TestVerifySecretData_MissingKeyOK: some providers (e.g. AWS ACM without
// exportable key material) legitimately have no private key — CertSyncer's
// KeystoreSkipped path relies on an absent tls.key not being an error.
func TestVerifySecretData_MissingKeyOK(t *testing.T) {
	certPEM, _, _ := genCert(t, "leaf", false, nil, nil)
	data := map[string][]byte{"tls.crt": certPEM}
	if err := VerifySecretData(data); err != nil {
		t.Fatalf("VerifySecretData: want nil for absent tls.key, got %v", err)
	}
}
