package controller

import (
	"bytes"
	"testing"

	ks "github.com/pavlo-v-chernykh/keystore-go/v4"

	"github.com/arindraaribudi/cert-manager-ext-issuer-secret-manager/internal/keystore"
)

// TestBuildKeystore_IncludesCompletedRootChain reproduces the gap found
// after wiring CompleteChain into tls.crt: BuildKeystore used to be called
// with the pre-completion leaf/chain, so tls.crt gained the root but
// keystore.jks/keystore.p12 silently didn't. This exercises the same
// split-from-tlsCrt path certsync.go now uses.
func TestBuildKeystore_IncludesCompletedRootChain(t *testing.T) {
	rootPEM, rootCert, rootKey := genCert(t, "root", true, nil, nil)
	intermediatePEM, interCert, interKey := genCert(t, "intermediate", true, rootCert, rootKey)
	leafPEM, _, leafKey := genCert(t, "leaf", false, interCert, interKey)
	keyPEM := genKeyPEM(t, leafKey)

	tlsCrt := NormalizePEM(append(append([]byte{}, leafPEM...), intermediatePEM...))
	tlsCrt = completeChain(tlsCrt, [][]byte{rootPEM}) // simulate a matching known root

	keystoreLeaf, keystoreChain := keystore.SplitLeafAndChain(tlsCrt)
	jks, _, pw, skipped, err := BuildKeystore(keystoreLeaf, keyPEM, keystoreChain, nil, "srchash")
	if err != nil {
		t.Fatalf("BuildKeystore: %v", err)
	}
	if skipped {
		t.Fatal("BuildKeystore: unexpectedly skipped")
	}

	store := ks.New()
	if err := store.Load(bytes.NewReader(jks), pw); err != nil {
		t.Fatalf("load generated JKS: %v", err)
	}
	// One PrivateKeyEntry (leaf) + one TrustedCertificateEntry per chain
	// cert (intermediate, root) = 3 aliases total.
	if n := len(store.Aliases()); n != 3 {
		t.Fatalf("JKS aliases = %d, want 3 (leaf privatekey + intermediate + root trusted entries): %v", n, store.Aliases())
	}
	if !store.IsTrustedCertificateEntry("chain-0") || !store.IsTrustedCertificateEntry("chain-1") {
		t.Fatalf("JKS missing expected chain-0/chain-1 trusted entries: %v", store.Aliases())
	}
}
