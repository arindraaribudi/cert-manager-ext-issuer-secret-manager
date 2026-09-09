package controller

import (
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
)

// SetReady updates the Ready condition on a Certificate.
func SetReady(c *cmapi.Certificate, ok bool, reason, msg string) {
	setter := cmapi.CertificateConditionReady
	status := cmmeta.ConditionFalse
	if ok {
		status = cmmeta.ConditionTrue
	}
	c.Status.Conditions = appendOrReplace(c.Status.Conditions, cmapi.CertificateCondition{
		Type:    setter,
		Status:  status,
		Reason:  reason,
		Message: msg,
	})
}

// SetSynced updates the Synced-ish condition on a Certificate.
// ponytail: cert-manager's Certificate has Ready + Issuing; we use Ready
// with reason="Drift" to signal source/cluster mismatch (good-enough for v1).
func SetSynced(c *cmapi.Certificate, ok bool, reason, msg string) {
	SetReady(c, ok, reason, msg)
}

func appendOrReplace(conds []cmapi.CertificateCondition, c cmapi.CertificateCondition) []cmapi.CertificateCondition {
	for i, existing := range conds {
		if existing.Type == c.Type {
			conds[i] = c
			return conds
		}
	}
	return append(conds, c)
}
