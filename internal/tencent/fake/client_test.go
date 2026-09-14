package fake

import (
	"context"
	"testing"
)

func TestFakeClient_Fetch(t *testing.T) {
	c := New()
	want := []byte("cert-pem-bytes")
	c.Set("abc123", want)

	got, err := c.Fetch(context.Background(), "abc123")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Errorf("got %q want %q", got, want)
	}
}
