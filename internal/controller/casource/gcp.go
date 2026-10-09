// Package casource — GCP adapter.
// Fetches a CA JSON payload from GCP Secret Manager via the existing
// internal/gcp client. Per-call client construction; ADC chain handles
// Workload Identity automatically. No static-creds path yet — SecretRef
// is unused until a user asks.
package casource

import (
	"context"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	"github.com/arindraaribudi/cert-manager-ext-issuer-secret-manager/internal/gcp"
	api "github.com/arindraaribudi/cert-manager-ext-issuer-secret-manager/api/v1alpha1"
)

const gcpPrefix = "gcp"

// GCPReconciler reconciles GCPSecretManagerCASource.
type GCPReconciler struct {
	*Reconciler
}

func (r *GCPReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var src api.GCPSecretManagerCASource
	if err := r.Get(ctx, req.NamespacedName, &src); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	in := ReconcileInput{
		Project:        src.Spec.Project,
		Endpoint:       src.Spec.Endpoint,
		SecretName:     src.Spec.SecretName,
		TargetNS:       src.Spec.Target.Namespace,
		TargetName:     src.Spec.Target.Name,
		ResyncInterval: src.Spec.ResyncInterval.Duration,
	}
	result, status, err := r.Reconciler.Reconcile(ctx, in, src.Status.Conditions)
	if err != nil {
		return ctrl.Result{}, r.markError(ctx, &src, err)
	}
	src.Status.Conditions = status.Conditions
	src.Status.SourceHash = status.SourceHash
	src.Status.LastSyncTime = status.LastSyncTime
	return result, r.Status().Update(ctx, &src)
}

func (r *GCPReconciler) markError(ctx context.Context, src *api.GCPSecretManagerCASource, err error) error {
	src.Status.Conditions = appendOrReplace(src.Status.Conditions, metav1.Condition{
		Type:    conditionReady,
		Status:  metav1.ConditionFalse,
		Reason:  "SyncFailed",
		Message: err.Error(),
	})
	return r.Status().Update(ctx, src)
}

func (r *GCPReconciler) SetupWithManager(mgr manager.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&api.GCPSecretManagerCASource{}).
		Complete(r)
}

// NewGCPFetch returns a Fetch closure for GCP Secret Manager. No
// caching — SDK client construction is cheap and per-call is simpler
// than a (project × endpoint) cache key.
func NewGCPFetch() FetchFunc {
	return func(ctx context.Context, spec FetchSpec) ([]byte, error) {
		cli, err := gcp.New(ctx, nil, spec.Endpoint)
		if err != nil {
			return nil, fmt.Errorf("gcp: new client: %w", err)
		}
		ref := fmt.Sprintf("projects/%s/secrets/%s/versions/latest", spec.Project, spec.SecretName)
		return gcp.Fetch(ctx, cli, ref)
	}
}
