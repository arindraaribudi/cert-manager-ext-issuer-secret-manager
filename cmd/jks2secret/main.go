// jks2secret converts a source JKS or PKCS#12 keystore into the
// AWS Secrets Manager / GCP Secret Manager JSON payload shape
// (certificate, private_key, certificate_chain — PEM strings) that
// the cert-manager-ext-issuer-secret-manager controller reads from
// the cloud. After writing the JSON it cross-checks every
// certificate and the private key against the source so a broken
// conversion fails loudly instead of silently shipping a corrupt
// payload.
//
// Usage:
//
//	jks2secret -source keystore.jks -password-file pw.txt \
//	           -name my-cert -out payload.json
//
// Source may be a JKS (keystore-go) or PKCS#12 (software.sslmate.com
// go-pkcs12) — auto-detected by trying JKS first. Keyless truststores
// produce a payload with empty private_key (just certificate +
// certificate_chain).
package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"os"
	"sort"

	ks "github.com/pavlo-v-chernykh/keystore-go/v4"
	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

// sourceKeystore is the in-memory view of a source JKS/PKCS#12: a
// single leaf (may be nil for a truststore) + its full chain. The
// private key is PKCS#8 DER (nil for truststores).
type sourceKeystore struct {
	leaf    *x509.Certificate
	chain   []*x509.Certificate // leaf NOT included
	keyDER  []byte              // PKCS#8 DER, nil for truststore
	isP12   bool                // true if source was PKCS#12, false if JKS
	keyless bool                // true if no private key
}

func Main() int {
	src := flag.String("source", "", "path to source JKS or PKCS#12 keystore (required)")
	trustSrc := flag.String("truststore", "", "optional: path to a JKS/PKCS#12 truststore whose CA certs are unioned into the generated certificate_chain")
	pwFile := flag.String("password-file", "", "file containing -source password (use -password for inline)")
	pwInline := flag.String("password", "", "-source password (prefer -password-file)")
	tpwFile := flag.String("truststore-password-file", "", "file containing -truststore password (defaults to -password if -truststore is set)")
	tpwInline := flag.String("truststore-password", "", "-truststore password (defaults to -password)")
	out := flag.String("out", "", "output JSON path (default: stdout)")
	skipVerify := flag.Bool("skip-verify", false, "skip source-vs-generated cross-check (NOT recommended)")
	flag.Parse()

	if *src == "" {
		fmt.Fprintln(os.Stderr, "jks2secret: -source is required")
		flag.Usage()
		return 2
	}
	if *pwFile == "" && *pwInline == "" {
		fmt.Fprintln(os.Stderr, "jks2secret: -password or -password-file is required")
		return 2
	}

	password := readSecret(*pwFile, *pwInline, "source")
	trustPassword := password
	if *trustSrc != "" && (*tpwFile != "" || *tpwInline != "") {
		trustPassword = readSecret(*tpwFile, *tpwInline, "truststore")
	}
	if *trustSrc != "" && len(password) == 0 && *tpwFile == "" && *tpwInline == "" {
		fmt.Fprintln(os.Stderr, "jks2secret: -truststore set but no password available; supply -password-file (applies to both), or -truststore-password-file, or -truststore-password")
		return 2
	}

	srcBytes, err := os.ReadFile(*src)
	if err != nil {
		log.Fatalf("read source: %v", err)
	}

	sk, err := loadSource(srcBytes, password)
	if err != nil {
		log.Fatalf("parse source %s: %v", *src, err)
	}
	if sk.leaf == nil {
		log.Fatalf("source has no leaf certificate; truststore-only inputs not yet supported")
	}
	log.Printf("source: leaf CN=%q, %d chain certs, key=%s",
		sk.leaf.Subject.CommonName, len(sk.chain), keyStatus(sk.keyDER))

	// Optional truststore: load CAs and union them into the chain. The
	// generated JKS / P12 then carry every CA the application needs to
	// trust, not just the ones bundled with the leaf.
	var truststoreFPs map[string]bool
	if *trustSrc != "" {
		tsBytes, err := os.ReadFile(*trustSrc)
		if err != nil {
			log.Fatalf("read truststore: %v", err)
		}
		ts, err := loadSource(tsBytes, trustPassword)
		if err != nil {
			log.Fatalf("parse truststore %s: %v", *trustSrc, err)
		}
		if !ts.keyless {
			log.Fatalf("truststore %s contains a private key; expected a keyless truststore", *trustSrc)
		}
		// Union: keep ts.leaf if it isn't already in sk.chain, plus every
		// other truststore cert. Dedup by fingerprint against both leaf +
		// sk.chain so the generated chain has no duplicates.
		seen := map[string]bool{fp(sk.leaf.Raw): true}
		for _, c := range sk.chain {
			seen[fp(c.Raw)] = true
		}
		truststoreFPs = map[string]bool{}
		newFromTrust := 0
		for _, c := range append([]*x509.Certificate{ts.leaf}, ts.chain...) {
			f := fp(c.Raw)
			truststoreFPs[f] = true
			if !seen[f] {
				sk.chain = append(sk.chain, c)
				seen[f] = true
				newFromTrust++
			}
		}
		log.Printf("truststore: %d unique CAs (%d new in addition to source chain)",
			len(truststoreFPs), newFromTrust)
	}

	leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: sk.leaf.Raw})
	var chainPEM []byte
	for _, c := range sk.chain {
		chainPEM = append(chainPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})...)
	}

	// SM JSON payload: certificate = leaf, certificate_chain = CAs only
	// (no leaf duplication — matches the upstream source shape the
	// controller reads). Truststore CAs were already unioned into
	// sk.chain above, so they flow through here for free.
	payload := smPayload{
		Certificate:      string(leafPEM),
		CertificateChain: string(chainPEM),
	}
	if len(sk.keyDER) > 0 {
		payload.PrivateKey = string(pemEncodePKCS8(sk.keyDER))
	}

	doc, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		log.Fatalf("json.Marshal: %v", err)
	}
	doc = append(doc, '\n')
	if *out != "" {
		if err := os.WriteFile(*out, doc, 0o600); err != nil {
			log.Fatalf("write %s: %v", *out, err)
		}
		log.Printf("wrote %s (%d bytes)", *out, len(doc))
	} else {
		os.Stdout.Write(doc)
	}

	if *skipVerify {
		log.Printf("verify: SKIPPED (--skip-verify)")
		return 0
	}
	if err := verifyPayload(payload, sk, truststoreFPs); err != nil {
		log.Fatalf("VERIFY FAILED: %v", err)
	}
	if truststoreFPs != nil {
		log.Printf("verify: source + truststore ↔ generated match (leaf + %d chain incl. %d truststore CAs + key)",
			len(sk.chain), len(truststoreFPs))
	} else {
		if len(sk.keyDER) > 0 {
			log.Printf("verify: source ↔ generated match (leaf + %d chain + key)", len(sk.chain))
		} else {
			log.Printf("verify: source ↔ generated match (leaf + %d chain, keyless)", len(sk.chain))
		}
	}
	return 0
}

// smPayload mirrors the cloud-side Secret payload the controller reads
// (see README §Sample and internal/controller/parse.go). PEM strings,
// not base64 — encoding/json's default HTML-escaping would mangle PEM
// without json.RawMessage handling, but PEM only uses ASCII so the
// default behavior is safe.
type smPayload struct {
	Certificate      string `json:"certificate"`
	PrivateKey       string `json:"private_key"`
	CertificateChain string `json:"certificate_chain"`
}

func main() { os.Exit(Main()) }

// readSecret returns the password bytes for one of the input keystores.
// -file flag wins; inline flag is the fallback. name is used for error
// messages only.
func readSecret(pwFile, pwInline, name string) []byte {
	switch {
	case pwFile != "":
		b, err := os.ReadFile(pwFile)
		if err != nil {
			log.Fatalf("read %s password file: %v", name, err)
		}
		return bytes.TrimRight(b, "\r\n")
	case pwInline != "":
		return []byte(pwInline)
	default:
		return nil
	}
}

// sniffKeystoreFormat returns the detected keystore format
// ("JKS" / "PKCS#12") or ("", false) when the input is neither.
// Magic bytes only — does not verify the password or parse the
// structure. ponytail: fail-fast on non-keystore input so callers
// get a clear "unsupported format" instead of a misleading
// "decryption password incorrect" from the PKCS#12 path.
func sniffKeystoreFormat(b []byte) (string, bool) {
	if len(b) >= 4 && binary.BigEndian.Uint32(b[:4]) == 0xFEEDFEED {
		return "JKS", true
	}
	// PKCS#12 outer wrapper is a PKCS#7 SignedData/CMS structure,
	// an ASN.1 SEQUENCE (tag 0x30) with a valid DER length prefix.
	if len(b) >= 2 && b[0] == 0x30 {
		return "PKCS#12", true
	}
	return "", false
}

// loadSource tries JKS first (keystore-go magic header); on failure
// falls back to PKCS#12. PKCS#12 is read twice if it has both key +
// trust entries (DecodeChain for the keyed half, DecodeTrustStore
// would over-collect on a keyed p12 — so we use only DecodeChain
// which returns the leaf + ca certs).
func loadSource(b, password []byte) (*sourceKeystore, error) {
	format, ok := sniffKeystoreFormat(b)
	if !ok {
		prefix := b
		if len(prefix) > 8 {
			prefix = prefix[:8]
		}
		return nil, fmt.Errorf("unsupported keystore format (first bytes: %x); expected JKS or PKCS#12", prefix)
	}

	store := ks.New()
	if err := store.Load(bytes.NewReader(b), password); err == nil {
		return fromJKS(store, password)
	}
	key, leaf, cas, err := pkcs12.DecodeChain(b, string(password))
	if err != nil {
		// Keyless PKCS#12 (truststore) — DecodeChain refuses without a
		// private key. Fall back to DecodeTrustStore.
		trustCerts, trustErr := pkcs12.DecodeTrustStore(b, string(password))
		if trustErr != nil {
			return nil, fmt.Errorf("invalid password for %s keystore: %w (trust store fallback: %v)", format, err, trustErr)
		}
		if len(trustCerts) == 0 {
			return nil, fmt.Errorf("not JKS and not PKCS#12: %w", err)
		}
		return &sourceKeystore{
			leaf:    trustCerts[0],
			chain:   trustCerts[1:],
			isP12:   true,
			keyless: true,
		}, nil
	}
	sk := &sourceKeystore{leaf: leaf, isP12: true}
	// pkcs12.DecodeChain returns the leaf in caCerts when the source
	// bundled the self-signed cert into the chain (common for tools
	// that always emit a complete chain). Strip the duplicate so chain
	// holds CAs only.
	leafFP := fp(leaf.Raw)
	for _, c := range cas {
		if fp(c.Raw) == leafFP {
			continue
		}
		sk.chain = append(sk.chain, c)
	}
	if key != nil {
		der, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return nil, fmt.Errorf("marshal p12 key: %w", err)
		}
		sk.keyDER = der
	} else {
		sk.keyless = true
	}
	return sk, nil
}

func fromJKS(store ks.KeyStore, password []byte) (*sourceKeystore, error) {
	sk := &sourceKeystore{}
	var keyAlias string
	for _, a := range store.Aliases() {
		switch {
		case store.IsPrivateKeyEntry(a):
			keyAlias = a
		case store.IsTrustedCertificateEntry(a):
			te, _ := store.GetTrustedCertificateEntry(a)
			c, err := x509.ParseCertificate(te.Certificate.Content)
			if err != nil {
				return nil, fmt.Errorf("parse trust cert %s: %w", a, err)
			}
			sk.chain = append(sk.chain, c)
		}
	}
	if keyAlias != "" {
		entry, err := store.GetPrivateKeyEntry(keyAlias, password)
		if err != nil {
			return nil, fmt.Errorf("get privkey %s: %w", keyAlias, err)
		}
		chain, err := store.GetPrivateKeyEntryCertificateChain(keyAlias)
		if err != nil {
			return nil, fmt.Errorf("get chain %s: %w", keyAlias, err)
		}
		if len(chain) > 0 {
			sk.leaf, err = x509.ParseCertificate(chain[0].Content)
			if err != nil {
				return nil, fmt.Errorf("parse leaf: %w", err)
			}
			for _, c := range chain[1:] {
				cc, err := x509.ParseCertificate(c.Content)
				if err != nil {
					return nil, fmt.Errorf("parse chain cert: %w", err)
				}
				sk.chain = append(sk.chain, cc)
			}
		}
		if len(entry.PrivateKey) > 0 {
			sk.keyDER = entry.PrivateKey // already PKCS#8 DER
		}
	} else if len(sk.chain) > 0 {
		// Truststore only — promote first trust entry to "leaf" so the
		// generated Secret has a tls.crt. Reject the case where caller
		// expected a keyed keystore (handled by Main).
		sk.leaf = sk.chain[0]
		sk.chain = sk.chain[1:]
		sk.keyless = true
	}
	return sk, nil
}

func pemEncodePKCS8(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

func keyStatus(der []byte) string {
	if len(der) == 0 {
		return "absent (truststore)"
	}
	return fmt.Sprintf("%d bytes PKCS#8", len(der))
}

// verifyPayload re-parses the generated SM JSON payload and confirms
// the certificate set (leaf + every chain cert) and the private key
// match the source. certificate_chain must contain exactly the source
// CAs (not the leaf — leaf goes in certificate, no duplication). If
// truststoreFPs is non-nil, every truststore fingerprint must appear
// in certificate_chain — so the cloud payload ships every CA the
// consumer needs. Fails with a diff on the first mismatch.
func verifyPayload(p smPayload, src *sourceKeystore, truststoreFPs map[string]bool) error {
	srcFPs := fpSet([]*x509.Certificate{src.leaf}, src.chain)
	log.Printf("verify: source fingerprint set: %s", joinFPs(srcFPs))

	// certificate must be exactly the source leaf.
	leafFP := fp(src.leaf.Raw)
	if blk, _ := pem.Decode([]byte(p.Certificate)); blk == nil || blk.Type != "CERTIFICATE" {
		return fmt.Errorf("certificate: not a CERTIFICATE PEM block")
	} else if fp(blk.Bytes) != leafFP {
		return fmt.Errorf("certificate fingerprint %s != source leaf %s", fp(blk.Bytes)[:12], leafFP[:12])
	}

	// certificate_chain = source CAs only, no leaf.
	chainFPs := fpSetFromPEM([]byte(p.CertificateChain))
	chainSrcFPs := map[string]bool{}
	for _, c := range src.chain {
		chainSrcFPs[fp(c.Raw)] = true
	}
	if !sameSet(chainFPs, chainSrcFPs) {
		return fmt.Errorf("certificate_chain fingerprint set %s != source chain %s", joinFPs(chainFPs), joinFPs(chainSrcFPs))
	}
	if chainFPs[leafFP] {
		return fmt.Errorf("certificate_chain must not contain the leaf (use certificate for that)")
	}

	// private_key: parse PKCS#8 PEM and compare DER.
	if src.keyless {
		if p.PrivateKey != "" {
			return fmt.Errorf("private_key present but source is keyless truststore")
		}
	} else {
		if p.PrivateKey == "" {
			return fmt.Errorf("private_key missing but source has a key")
		}
		blk, _ := pem.Decode([]byte(p.PrivateKey))
		if blk == nil || blk.Type != "PRIVATE KEY" {
			return fmt.Errorf("private_key not PKCS#8 PEM")
		}
		if !bytes.Equal(blk.Bytes, src.keyDER) {
			return fmt.Errorf("private_key DER != source PKCS#8 DER (src %d bytes, gen %d bytes)",
				len(src.keyDER), len(blk.Bytes))
		}
	}

	// Truststore cross-check: every truststore CA must be in the
	// emitted certificate_chain so consumers don't need a second
	// payload to complete trust.
	if len(truststoreFPs) > 0 {
		for f := range truststoreFPs {
			if !chainFPs[f] {
				return fmt.Errorf("truststore CA fp=%s missing from certificate_chain", f)
			}
		}
	}
	return nil
}

func fp(der []byte) string { s := sha256.Sum256(der); return fmt.Sprintf("%x", s) }

func fpSet(leafs, chain []*x509.Certificate) map[string]bool {
	m := map[string]bool{}
	for _, c := range append(append([]*x509.Certificate{}, leafs...), chain...) {
		if c != nil {
			m[fp(c.Raw)] = true
		}
	}
	return m
}

func fpSetFromPEM(pemBytes []byte) map[string]bool {
	m := map[string]bool{}
	rest := pemBytes
	for {
		var blk *pem.Block
		blk, rest = pem.Decode(rest)
		if blk == nil {
			break
		}
		if blk.Type != "CERTIFICATE" {
			continue
		}
		m[fp(blk.Bytes)] = true
	}
	return m
}

func sameSet(a, b map[string]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if !b[k] {
			return false
		}
	}
	return true
}

func joinFPs(m map[string]bool) string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k[:12])
	}
	sort.Strings(out)
	return fmt.Sprintf("%v", out)
}
