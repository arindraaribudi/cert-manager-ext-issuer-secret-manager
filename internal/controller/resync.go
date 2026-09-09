// Package controller — Resyncer runs a periodic drift check across all
// Issuers + ClusterIssuers. ponytail: re-uses Hash; ticker interval from
// Options.ResyncInterval. Drift body is deferred to a follow-up (T16.5).
package controller

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"time"

	"sigs.k8s.io/controller-runtime/pkg/manager"
)

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
	Interval time.Duration
}

// Start implements manager.Runnable. The drift body is deferred (T16.5
// follow-up); today the ticker is a no-op loop. Keep this thin — the
// reconciler's SetReady covers immediate misses, this is best-effort late
// detection only.
func (r *Resyncer) Start(ctx context.Context) error {
	if r.Interval <= 0 {
		// Disable ticker if interval not set (useful for tests).
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
			// ponytail: drift-check body deferred. See plan §10 self-review.
		}
	}
}

// Compile-time assertion that Resyncer satisfies manager.Runnable.
var _ manager.Runnable = (*Resyncer)(nil)
