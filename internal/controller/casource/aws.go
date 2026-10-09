// Package casource — AWS adapter.
// Fetches a CA JSON payload from AWS Secrets Manager via the existing
// internal/aws client. SDK client is cached by region|endpoint when
// the CASource uses the default credential chain (IRSA / Pod Identity);
// rebuilt per-call when the spec supplies static AK/SK via SecretRef.
package casource

import (
	"context"
	"fmt"
	"sync"

	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	awscertpkg "github.com/arindraaribudi/cert-manager-ext-issuer-secret-manager/internal/awscert"
	awssdk "github.com/arindraaribudi/cert-manager-ext-issuer-secret-manager/internal/aws"
	api "github.com/arindraaribudi/cert-manager-ext-issuer-secret-manager/api/v1alpha1"
)

// AWSReconciler reconciles AWSSecretManagerCASource.
type AWSReconciler struct {
	*Reconciler
}

func (r *AWSReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var src api.AWSSecretManagerCASource
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

func (r *AWSReconciler) markError(ctx context.Context, src *api.AWSSecretManagerCASource, err error) error {
	src.Status.Conditions = appendOrReplace(src.Status.Conditions, metav1.Condition{
		Type:    conditionReady,
		Status:  metav1.ConditionFalse,
		Reason:  "SyncFailed",
		Message: err.Error(),
	})
	return r.Status().Update(ctx, src)
}

func (r *AWSReconciler) SetupWithManager(mgr manager.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&api.AWSSecretManagerCASource{}).
		Complete(r)
}

// NewAWSFetch returns a Fetch closure for AWS Secrets Manager. Captures
// kube + cmNamespace at construction so the static-creds path can
// resolve spec.SecretRef without an extra indirection layer.
// ponytail: default-chain client cached by region|endpoint (SDK clients
// are safe for concurrent use); static-creds client rebuilt per call.
func NewAWSFetch(kube client.Client, cmNamespace string) FetchFunc {
	var mu sync.Mutex
	cache := map[string]*awssdk.Client{}
	return func(ctx context.Context, spec FetchSpec) ([]byte, error) {
		if spec.SecretRef != nil {
			ns := spec.SecretRef.Namespace
			if ns == "" {
				ns = cmNamespace
			}
			cfg, err := awscertpkg.LoadStaticCredentials(ctx, kube, spec.SecretRef.Name, ns)
			if err != nil {
				return nil, fmt.Errorf("aws: load static creds: %w", err)
			}
			cfg.Region = spec.Region
			if spec.Endpoint != "" {
				ep := spec.Endpoint
				cfg.BaseEndpoint = &ep
			}
			return awssdk.Wrap(secretsmanager.NewFromConfig(cfg)).Fetch(ctx, spec.SecretName)
		}

		key := spec.Region + "|" + spec.Endpoint
		mu.Lock()
		cli, ok := cache[key]
		if !ok {
			c, err := awssdk.New(ctx, spec.Region, spec.Endpoint)
			if err != nil {
				mu.Unlock()
				return nil, fmt.Errorf("aws: new client: %w", err)
			}
			cache[key] = c
			cli = c
		}
		mu.Unlock()
		return cli.Fetch(ctx, spec.SecretName)
	}
}
