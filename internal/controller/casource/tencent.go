// Package casource — Tencent adapter.
// Fetches a CA JSON payload from Tencent SSM via the existing
// internal/tencent client. Credentials resolve via TKE OIDC pod
// identity when env is bound (preferred), or static AK/SK from
// spec.SecretRef as fallback. SDK client cached by region|endpoint.
package casource

import (
	"context"
	"fmt"
	"sync"

	tcssm "github.com/tencentcloud/tencentcloud-sdk-go-intl-en/tencentcloud/ssm/v20190923"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	"github.com/arindraaribudi/cert-manager-ext-issuer-secret-manager/internal/tencent"
	api "github.com/arindraaribudi/cert-manager-ext-issuer-secret-manager/api/v1alpha1"
)

// TencentReconciler reconciles TencentSecretManagerCASource.
type TencentReconciler struct {
	*Reconciler
}

func (r *TencentReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var src api.TencentSecretManagerCASource
	if err := r.Get(ctx, req.NamespacedName, &src); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	in := ReconcileInput{
		Region:         src.Spec.Region,
		Endpoint:       src.Spec.Endpoint,
		SecretName:     src.Spec.SecretName,
		SecretRef:      src.Spec.SecretRef,
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

func (r *TencentReconciler) markError(ctx context.Context, src *api.TencentSecretManagerCASource, err error) error {
	src.Status.Conditions = appendOrReplace(src.Status.Conditions, metav1.Condition{
		Type:    conditionReady,
		Status:  metav1.ConditionFalse,
		Reason:  "SyncFailed",
		Message: err.Error(),
	})
	return r.Status().Update(ctx, src)
}

func (r *TencentReconciler) SetupWithManager(mgr manager.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&api.TencentSecretManagerCASource{}).
		Complete(r)
}

// NewTencentFetch returns a Fetch closure for Tencent SSM. Caches the
// SDK client by region|endpoint. Credential resolution (TKE OIDC vs
// static AK/SK) is per-call — static creds vary per CRD, so caching
// across CRDs would need a composite key we don't need yet.
// ponytail: matches internal/app/app.go:346-379 (the existing resolver
// pattern). OIDC provider handles STS token refresh internally.
func NewTencentFetch(kube client.Client, cmNamespace string) FetchFunc {
	var mu sync.Mutex
	cache := map[string]*tcssm.Client{}
	return func(ctx context.Context, spec FetchSpec) ([]byte, error) {
		ns := ""
		if spec.SecretRef != nil {
			ns = spec.SecretRef.Namespace
			if ns == "" {
				ns = cmNamespace
			}
		}
		cred, err := tencent.ResolveCredential(ctx, kube, nsOrEmpty(spec.SecretRef), ns)
		if err != nil {
			return nil, fmt.Errorf("tencent: resolve credential: %w", err)
		}
		key := spec.Region + "|" + spec.Endpoint
		mu.Lock()
		cli, ok := cache[key]
		if !ok {
			c, err := tencent.New(ctx, spec.Region, cred, spec.Endpoint)
			if err != nil {
				mu.Unlock()
				return nil, fmt.Errorf("tencent: new client: %w", err)
			}
			cache[key] = c
			cli = c
		}
		mu.Unlock()
		return tencent.Fetch(ctx, cli, spec.SecretName)
	}
}

func nsOrEmpty(ref *api.SecretRef) string {
	if ref == nil {
		return ""
	}
	return ref.Name
}
