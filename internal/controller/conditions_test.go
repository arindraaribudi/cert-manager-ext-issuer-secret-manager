package controller

import (
	"testing"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestSetReady(t *testing.T) {
	c := &cmapi.Certificate{}
	SetReady(c, true, "OK", "all good")
	if c.Status.Conditions[0].Type != cmapi.CertificateConditionReady {
		t.Fatalf("type = %v", c.Status.Conditions[0].Type)
	}
	if c.Status.Conditions[0].Status != cmmeta.ConditionTrue {
		t.Fatalf("status = %v", c.Status.Conditions[0].Status)
	}
}

func TestSetSynced(t *testing.T) {
	c := &cmapi.Certificate{ObjectMeta: metav1.ObjectMeta{Name: "x"}}
	SetSynced(c, false, "Drift", "cloud cert differs from k8s secret")
	cond := c.Status.Conditions[0]
	if cond.Reason != "Drift" || cond.Message != "cloud cert differs from k8s secret" {
		t.Errorf("unexpected condition: %+v", cond)
	}
}
