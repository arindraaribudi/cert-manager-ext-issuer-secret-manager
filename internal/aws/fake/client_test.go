package fake

import (
	"context"
	"testing"
)

func TestFakeClient_Fetch(t *testing.T) {
	c := New()
	want := []byte("cert-bytes")
	c.Set("my-secret", want)

	got, err := c.Fetch(context.Background(), "my-secret")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Errorf("got %q want %q", got, want)
	}
}

func TestFakeClient_FetchNotFound(t *testing.T) {
	c := New()
	_, err := c.Fetch(context.Background(), "nope")
	if err == nil {
		t.Fatal("expected error for missing secret")
	}
}
