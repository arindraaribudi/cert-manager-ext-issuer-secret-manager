package controller

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func stamped(data map[string][]byte, src string) *corev1.Secret {
	s := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{AnnotationSourceHash: src}},
		Type:       corev1.SecretTypeTLS,
		Data:       data,
	}
	s.Annotations[AnnotationSecretHash] = HashSecretData(s.Data)
	return s
}

func TestHashSecretData_NoConcatCollision(t *testing.T) {
	a := HashSecretData(map[string][]byte{"a": []byte("xy"), "b": []byte("z")})
	b := HashSecretData(map[string][]byte{"a": []byte("x"), "b": []byte("yz")})
	if a == b {
		t.Fatal("distinct Data maps hashed equal")
	}
}

func TestSourceHash_NoFieldCollision(t *testing.T) {
	if SourceHash([]byte("ab"), []byte("c"), nil) == SourceHash([]byte("a"), []byte("bc"), nil) {
		t.Fatal("distinct PEM splits hashed equal")
	}
}

func TestSecretUpToDate(t *testing.T) {
	data := map[string][]byte{"tls.crt": []byte("crt"), "keystore.p12": []byte("p12")}

	t.Run("identical is up to date", func(t *testing.T) {
		if !secretUpToDate(stamped(data, "src1"), stamped(data, "src1")) {
			t.Fatal("want skip")
		}
	})

	t.Run("source rotated forces write", func(t *testing.T) {
		if secretUpToDate(stamped(data, "src1"), stamped(data, "src2")) {
			t.Fatal("want write")
		}
	})

	t.Run("keystore-only change forces write", func(t *testing.T) {
		next := map[string][]byte{"tls.crt": []byte("crt"), "keystore.p12": []byte("NEW")}
		if secretUpToDate(stamped(data, "src1"), stamped(next, "src1")) {
			t.Fatal("want write: old secretPayloadEqual ignored keystore keys")
		}
	})

	t.Run("out-of-band edit forces write", func(t *testing.T) {
		live := stamped(data, "src1")
		live.Data["tls.crt"] = []byte("tampered")
		if secretUpToDate(live, stamped(data, "src1")) {
			t.Fatal("want write")
		}
	})

	t.Run("unstamped legacy secret forces write", func(t *testing.T) {
		live := &corev1.Secret{Type: corev1.SecretTypeTLS, Data: data}
		if secretUpToDate(live, stamped(data, "src1")) {
			t.Fatal("want write")
		}
	})
}

func TestBuildKeystore_ReusesOnUnchangedSource(t *testing.T) {
	existing := stamped(map[string][]byte{
		"keystore.jks":      []byte("JKS"),
		"keystore.p12":      []byte("P12"),
		"keystore.password": []byte("PW"),
	}, "src1")

	jks, p12, pw, skipped, err := BuildKeystore([]byte("cert"), []byte("key"), nil, existing, "src1")
	if err != nil || skipped {
		t.Fatalf("err=%v skipped=%v", err, skipped)
	}
	if string(jks) != "JKS" || string(p12) != "P12" || string(pw) != "PW" {
		t.Fatal("want verbatim reuse of existing keystore bytes")
	}
}

func TestNormalizePEM_DropsRepeatedBlocks(t *testing.T) {
	// Same leaf repeated, as a Tencent ZIP delivers it across server-type dirs.
	one := "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"
	got := NormalizePEM([]byte(one + one + one))
	if string(got) != one {
		t.Fatalf("want single block, got %d bytes for a %d-byte block", len(got), len(one))
	}
}
