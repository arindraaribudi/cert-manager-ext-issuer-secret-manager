// Package controller — Resyncer runs a periodic drift check across all
// Certificates whose IssuerRef targets this controller. ponytail: re-uses
// Hash; ticker interval from Options.ResyncInterval.
package controller

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"time"

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
)

// IssuerGroup is the apiGroup this controller reconciles for. Matches the
// `issuerRef.group` stamped on every Certificate that should be routed here.
// ponytail: single source of truth — also used by the watch predicate in
// app.go so the controller doesn't wake up for cert-manager's built-in certs.
const IssuerGroup = "secret-manager.cert-manager.io"

// Hash returns sha256(b) as hex, or "" if b is empty.
func Hash(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// Resyncer runs the drift ticker. Wired up by the app via mgr.Add().
type Resyncer struct {
	//   Client lists Certificates. Required.
	Client client.Client
	//   Reconcile is the per-cert reconcile fn (typically IssuerReconciler.Reconcile).
	//   Required. Wrapped to swallow ctx-cancelled as graceful exit.
	Reconcile func(ctx context.Context, req ctrl.Request) (ctrl.Result, error)
	//   Interval between ticks. <=0 disables the ticker (kept alive by ctx).
	Interval time.Duration
}

// Start implements manager.Runnable. Each tick lists Certificates whose
// IssuerRef.Group matches ours and calls Reconcile for each. This catches
// (a) certs that became Ready before the controller started (no event
//     ever fires for them) and
// (b) cloud-side secret changes that don't produce a k8s event.
func (r *Resyncer) Start(ctx context.Context) error {
	if r.Client == nil || r.Reconcile == nil {
		return nil
	}
	if r.Interval <= 0 {
		<-ctx.Done()
		return nil
	}
	t := time.NewTicker(r.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			r.drift(ctx)
		}
	}
}

// drift lists Certificates for our group and re-reconciles each. Errors per
// cert are logged and skipped — one bad cert must not abort the loop.
// ponytail: direct Reconcile call (not queue) is intentional. Adds latency
// to the tick (sequential per-cert work) but is simple, deterministic, and
// won't race with the watch-driven reconcile for the same object.
func (r *Resyncer) drift(ctx context.Context) {
	l := log.FromContext(ctx)
	var certs cmapi.CertificateList
	if err := r.Client.List(ctx, &certs); err != nil {
		l.Error(err, "resync: list certificates")
		return
	}
	for i := range certs.Items {
		c := &certs.Items[i]
		if c.Spec.IssuerRef.Group != IssuerGroup {
			continue
		}
		req := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(c)}
		if _, err := r.Reconcile(ctx, req); err != nil {
			l.Error(err, "resync: reconcile", "certificate", client.ObjectKeyFromObject(c))
		}
	}
}

// Compile-time assertion that Resyncer satisfies manager.Runnable.
var _ manager.Runnable = (*Resyncer)(nil)
