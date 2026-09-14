package fake

import (
	"context"
	"testing"
)

func TestFakeClient_Fetch(t *testing.T) {
	c := New()
	want := []byte("gcp-payload")
	c.Set("projects/p/secrets/s/versions/latest", want)

	got, err := c.Fetch(context.Background(), "projects/p/secrets/s/versions/latest")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Errorf("got %q want %q", got, want)
	}
}
