package controller

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"

	corev1 "k8s.io/api/core/v1"

	"github.com/arindraaribudi/cert-manager-ext-issuer-secret-manager/internal/keystore"
)

const (
	// AnnotationSourceHash digests the cert material fetched from the cloud
	// provider. Unchanged value means the upstream cert has not rotated.
	AnnotationSourceHash = "external-issuer.cert-manager.io/source-hash"
	// AnnotationSecretHash digests Secret.Data as this controller last wrote
	// it. A mismatch against the live Data means someone edited the Secret
	// out-of-band, so the next reconcile rewrites it.
	AnnotationSecretHash = "external-issuer.cert-manager.io/secret-hash"
	// AnnotationLastSyncTime is the RFC3339 UTC timestamp of the reconcile
	// that last wrote this Secret.
	AnnotationLastSyncTime = "external-issuer.cert-manager.io/last-sync-time"
	// AnnotationChain describes the certificate types present in the
	// written Secret as a pipe-joined list in canonical order, e.g.
	// "leaf|intermediate|root" or "leaf|intermediate" when no root was
	// included. See ChainComposition.
	AnnotationChain = "external-issuer.cert-manager.io/chain"
)

// SourceHash digests the PEM material fetched from the provider.
//
// ponytail: hashes the derived PEM rather than the raw API response on
// purpose — ACM re-encrypts the exported private key with a fresh salt and
// Tencent re-zips with fresh timestamps on every call, so raw response bytes
// differ even when the certificate has not rotated.
func SourceHash(certPEM, keyPEM, chainPEM []byte) string {
	h := sha256.New()
	for _, p := range [][]byte{certPEM, keyPEM, chainPEM} {
		_, _ = fmt.Fprintf(h, "%d:", len(p))
		h.Write(p)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// HashSecretData digests Secret.Data. Keys are sorted and every field is
// length-prefixed so distinct maps cannot collide by concatenation.
func HashSecretData(data map[string][]byte) string {
	keys := make([]string, 0, len(data))
	for k := range data {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	h := sha256.New()
	for _, k := range keys {
		_, _ = fmt.Fprintf(h, "%d:%s:%d:", len(k), k, len(data[k]))
		h.Write(data[k])
	}
	return hex.EncodeToString(h.Sum(nil))
}

// BuildKeystore wraps keystore.Build, reusing the existing Secret's keystore
// bytes verbatim when srcHash matches what produced them.
//
// ponytail: JKS embeds a creation timestamp and PKCS#12 a random salt, so
// rebuilding from identical input still yields different bytes every
// reconcile — which would make the secret-hash comparison never match and
// re-write the Secret forever. Reusing on an unchanged source is both the
// cheaper and the correct path.
func BuildKeystore(certPEM, keyPEM, chainPEM []byte, existing *corev1.Secret, srcHash string) (jks, p12, password []byte, skipped bool, err error) {
	if existing != nil && srcHash != "" && existing.Annotations[AnnotationSourceHash] == srcHash {
		j, p, pw := existing.Data["keystore.jks"], existing.Data["keystore.p12"], existing.Data["keystore.password"]
		if len(j) > 0 && len(p) > 0 && len(pw) > 0 {
			return j, p, pw, false, nil
		}
	}
	return keystore.Build(certPEM, keyPEM, chainPEM, existing)
}
