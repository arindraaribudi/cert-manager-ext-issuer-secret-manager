package controller

import (
	"testing"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestSecretName(t *testing.T) {
	cases := []struct {
		name string
		ann  map[string]string
		want string
		ok   bool
	}{
		{"present", map[string]string{AnnotationSecretName: "abc"}, "abc", true},
		{"missing", map[string]string{}, "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := &cmapi.Certificate{ObjectMeta: metav1.ObjectMeta{Annotations: tc.ann}}
			got, ok := SecretName(c)
			if ok != tc.ok || got != tc.want {
				t.Errorf("got (%q,%v) want (%q,%v)", got, ok, tc.want, tc.ok)
			}
		})
	}
}

func TestIsForceSyncSet(t *testing.T) {
	c := &cmapi.Certificate{ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{AnnotationForceSync: "true"}}}
	if !IsForceSyncSet(c) {
		t.Fatal("expected true")
	}
	c2 := &cmapi.Certificate{ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{}}}
	if IsForceSyncSet(c2) {
		t.Fatal("expected false")
	}
}

func TestClearForceSync(t *testing.T) {
	c := &cmapi.Certificate{ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{AnnotationForceSync: "true"}}}
	ClearForceSync(c)
	if _, ok := c.Annotations[AnnotationForceSync]; ok {
		t.Fatal("annotation not cleared")
	}
}