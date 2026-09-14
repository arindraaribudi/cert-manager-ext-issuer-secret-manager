package app

import "testing"

func TestNormalizeGCPVersion(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		// No version → append /versions/latest.
		{"projects/p/secrets/s", "projects/p/secrets/s/versions/latest"},
		{"projects/p/secrets/s/", "projects/p/secrets/s/versions/latest"},
		// Already has version → leave alone.
		{"projects/p/secrets/s/versions/latest", "projects/p/secrets/s/versions/latest"},
		{"projects/p/secrets/s/versions/3", "projects/p/secrets/s/versions/3"},
	}
	for _, c := range cases {
		if got := normalizeGCPVersion(c.in); got != c.want {
			t.Errorf("normalizeGCPVersion(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}