// Package controller — annotation helpers.
package controller

import (
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
)

const (
	// AnnotationSecretName is the generic, provider-agnostic annotation that
	// tells the controller which cloud-side secret to fetch.
	AnnotationSecretName = "cert-manager.io/secret-manager-secret-name"

	// AnnotationForceSync forces a re-fetch from the source on next reconcile.
	AnnotationForceSync = "cert-manager.io/secret-manager-force-sync"
)

// SecretName returns the cloud-side identifier from the annotation.
func SecretName(c *cmapi.Certificate) (string, bool) {
	v, ok := c.Annotations[AnnotationSecretName]
	return v, ok && v != ""
}

// IsForceSyncSet returns true if the force-sync annotation is present.
func IsForceSyncSet(c *cmapi.Certificate) bool {
	_, ok := c.Annotations[AnnotationForceSync]
	return ok
}

// ClearForceSync removes the force-sync annotation. Caller is responsible
// for persisting the Certificate via Update/Status().Update.
func ClearForceSync(c *cmapi.Certificate) {
	delete(c.Annotations, AnnotationForceSync)
}