// Package controller — shared logging helpers used by every reconciler.
package controller

import (
	"context"
	"time"

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

// RequeueAfterError logs err and returns a 30s requeue Result with a nil
// error. Use this instead of `return ctrl.Result{}, err` to break the
// controller-runtime workqueue exponential backoff loop — `{}, err` ramps
// from 5ms → 1.28s → 16min, which fires the cert-manager Ready False→True
// transition log ~10x per second on persistent failures. 30s cap keeps
// reconciliation responsive without spamming the API server. Shared across
// awscert, tencentcert, and the secret-manager reconciler.
func RequeueAfterError(ctx context.Context, err error, msg string, keysAndValues ...any) ctrl.Result {
	log.FromContext(ctx).Error(err, msg, keysAndValues...)
	return ctrl.Result{RequeueAfter: 30 * time.Second}
}