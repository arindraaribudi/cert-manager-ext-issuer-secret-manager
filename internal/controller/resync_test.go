package controller

import (
	"testing"

	api "github.com/arindraaribudi/cert-manager-ext-issuer-secret-manager/api/v1alpha1"
)

func TestHash(t *testing.T) {
	got := Hash([]byte("hello"))
	if got == "" {
		t.Fatal("hash should not be empty")
	}
	// Deterministic
	if got != Hash([]byte("hello")) {
		t.Fatal("hash should be deterministic")
	}
	// Different input -> different hash
	if got == Hash([]byte("world")) {
		t.Fatal("different inputs should produce different hashes")
	}
}

func TestHash_Empty(t *testing.T) {
	if Hash([]byte{}) != "" {
		t.Fatal("empty input should produce empty hash")
	}
}

// Reference to keep api import alive (used elsewhere too)
var _ = api.SecretRef{}
