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

// ConditionTypeExternalIssuerSynced is a custom condition owned by our
// controllers — cert-manager ignores unknown condition types, so we can
// flip this without fighting cert-manager's own trigger loop on Ready.
// Operators read it to detect drift between the configured cloud source
// and the target Secret.
const ConditionTypeExternalIssuerSynced cmapi.CertificateConditionType = "ExternalIssuerSynced"

// SetExternalIssuerSynced updates the ExternalIssuerSynced condition.
// Idempotent via appendOrReplace. Safe to call alongside SetReady; the
// two conditions carry different intents (cert-manager owns Ready, we
// own ExternalIssuerSynced).
func SetExternalIssuerSynced(c *cmapi.Certificate, ok bool, reason, msg string) {
	status := cmmeta.ConditionFalse
	if ok {
		status = cmmeta.ConditionTrue
	}
	c.Status.Conditions = appendOrReplace(c.Status.Conditions, cmapi.CertificateCondition{
		Type:    ConditionTypeExternalIssuerSynced,
		Status:  status,
		Reason:  reason,
		Message: msg,
	})
}

// SetCRReady updates the Ready condition on a CertificateRequest and sets
// the certificate bytes (cert-manager's issuing controller watches CR
// Ready=True to assemble the target Secret).
func SetCRReady(cr *cmapi.CertificateRequest, cert, ca []byte, reason, msg string) {
	if len(cert) > 0 {
		cr.Status.Certificate = cert
	}
	if len(ca) > 0 {
		cr.Status.CA = ca
	}
	cr.Status.Conditions = appendOrReplaceCR(cr.Status.Conditions, cmapi.CertificateRequestCondition{
		Type:    cmapi.CertificateRequestConditionReady,
		Status:  cmmeta.ConditionTrue,
		Reason:  reason,
		Message: msg,
	})
}

func appendOrReplaceCR(conds []cmapi.CertificateRequestCondition, c cmapi.CertificateRequestCondition) []cmapi.CertificateRequestCondition {
	for i, existing := range conds {
		if existing.Type == c.Type {
			conds[i] = c
			return conds
		}
	}
	return append(conds, c)
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
