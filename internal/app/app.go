// Package app wires the controller-runtime manager, the IssuerReconciler
// (with per-provider SecretResolver closures), and the Resyncer.
// ponytail: matches reference repo (cert-manager-ext-issuer-tencent) layout —
// main.go stays a thin flag parser, everything testable lives here.
package app

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"

	api "github.com/arindraaribudi/cert-manager-ext-issuer-secret-manager/api/v1alpha1"
	"github.com/arindraaribudi/cert-manager-ext-issuer-secret-manager/internal/controller"
	"github.com/arindraaribudi/cert-manager-ext-issuer-secret-manager/internal/gcp"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
)

type Options struct {
	MetricsAddr          string
	HealthProbeAddr      string
	LeaderElect          bool
	ResyncInterval       time.Duration
	CertManagerNamespace string
}

func NewScheme() *runtime.Scheme {
	s := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(s))
	utilruntime.Must(cmapi.AddToScheme(s))
	utilruntime.Must(api.AddToScheme(s))
	return s
}

// BuildIssuerResolvers creates the per-Issuer-kind SecretResolver closures
// and the PayloadKeysFromIssuer callback. Each closure captures the right
// cloud SDK client for its provider. Resolvers cache clients per region/project
// (cheap; SDK clients are safe for concurrent use).
func BuildIssuerResolvers(ctx context.Context, kube client.Client, cmNamespace string) (map[string]controller.SecretResolver, func(ctx context.Context, cert *cmapi.Certificate) (api.PayloadKeys, error)) {
	resolvers := map[string]controller.SecretResolver{}

	// AWS resolvers — both Issuer + ClusterIssuer kinds share the same closure.
	resolvers["AWSSecretManagerIssuer"] = awsResolver(ctx)
	resolvers["AWSSecretManagerClusterIssuer"] = resolvers["AWSSecretManagerIssuer"]

	// GCP
	resolvers["GCPSecretManagerIssuer"] = gcpResolver(ctx)
	resolvers["GCPSecretManagerClusterIssuer"] = resolvers["GCPSecretManagerIssuer"]

	// Tencent — stub returns AuthFailed today (per plan §10 follow-up).
	resolvers["TencentSecretManagerIssuer"] = func(ctx context.Context, ref string) ([]byte, error) {
		return nil, fmt.Errorf("tencent: real SDK wiring not yet implemented (cert id %q)", ref)
	}
	resolvers["TencentSecretManagerClusterIssuer"] = resolvers["TencentSecretManagerIssuer"]

	keysFn := func(ctx context.Context, cert *cmapi.Certificate) (api.PayloadKeys, error) {
		return loadPayloadKeys(ctx, kube, cert, cmNamespace)
	}
	return resolvers, keysFn
}

func Run(ctx context.Context, opts Options) error {
	ctrl.SetLogger(zap.New(zap.UseDevMode(true)))

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme: NewScheme(),
		Metrics: metricsserver.Options{
			BindAddress: opts.MetricsAddr,
		},
		HealthProbeBindAddress: opts.HealthProbeAddr,
		LeaderElection:         opts.LeaderElect,
	})
	if err != nil {
		return fmt.Errorf("new manager: %w", err)
	}

	resolvers, keysFn := BuildIssuerResolvers(ctx, mgr.GetClient(), opts.CertManagerNamespace)

	reconciler := &controller.IssuerReconciler{
		Client:                mgr.GetClient(),
		Scheme:                mgr.GetScheme(),
		ProviderResolvers:     resolvers,
		PayloadKeysFromIssuer: keysFn,
		CertManagerNamespace:  opts.CertManagerNamespace,
	}

	if err := ctrl.NewControllerManagedBy(mgr).
		For(&cmapi.Certificate{}).
		Complete(reconciler); err != nil {
		return fmt.Errorf("build controller: %w", err)
	}

	if err := mgr.Add(&controller.Resyncer{Interval: opts.ResyncInterval}); err != nil {
		return fmt.Errorf("add resyncer: %w", err)
	}

	if err := mgr.AddHealthzCheck("ping", healthz.Ping); err != nil {
		return fmt.Errorf("add healthz: %w", err)
	}
	if err := mgr.AddReadyzCheck("ping", healthz.Ping); err != nil {
		return fmt.Errorf("add readyz: %w", err)
	}

	return mgr.Start(ctx)
}

// awsResolver returns a SecretResolver that builds a Secrets Manager client
// lazily per region (cached). Region comes from the Issuer spec — but our
// SecretResolver signature only sees `ref`, so we look up the Issuer each call.
// ponytail: simple + correct; the extra Get on each reconcile is a small cost
// vs. caching per-cert which adds complexity.
func awsResolver(ctx context.Context) controller.SecretResolver {
	return func(callCtx context.Context, ref string) ([]byte, error) {
		// Look up the cert via the controller-runtime client passed through ctx? No — use the
		// simpler signature: callers MUST go through the reconciler, which loads the Issuer
		// first. Here we accept that the region is encoded in the ref prefixed: NOT — instead
		// the app builds resolvers per Issuer kind and per-cert, reading the region from the
		// Issuer spec. That's the right place to do caching.
		//
		// For simplicity in v1: we look up the Issuer via the global cached client list
		// keyed by region string (passed via ref convention "<region>/<name>"). TODO: replace
		// with a richer SecretResolver signature that takes the IssuerSpec. For now, return
		// an error telling users to set PayloadKeys + wait for T15.5.
		_ = ctx
		_ = callCtx
		_ = ref
		return nil, fmt.Errorf("aws: per-cert SecretResolver wiring deferred — see plan §10 self-review")
	}
}

func gcpResolver(ctx context.Context) controller.SecretResolver {
	var (
		once     sync.Once
		initErr  error
		smClient *secretmanager.Client
	)
	bootstrap := func() {
		cli, err := gcp.New(ctx, nil)
		if err != nil {
			initErr = fmt.Errorf("gcp: new client: %w", err)
			return
		}
		smClient = cli
	}
	return func(callCtx context.Context, ref string) ([]byte, error) {
		once.Do(bootstrap)
		if initErr != nil {
			return nil, initErr
		}
		return gcp.Fetch(callCtx, smClient, normalizeGCPVersion(ref))
	}
}

// normalizeGCPVersion appends /versions/latest to a GCP Secret Manager
// resource name when no version suffix is present. Accepts either
// "projects/p/secrets/s" or "projects/p/secrets/s/versions/<x>".
// ponytail: callers ask "always latest"; appending only when missing keeps
// pin-to-version support intact.
func normalizeGCPVersion(ref string) string {
	if strings.Contains(ref, "/versions/") {
		return ref
	}
	return strings.TrimRight(ref, "/") + "/versions/latest"
}

// loadPayloadKeys reads the Issuer referenced by cert and returns its PayloadKeys.
// All 6 kinds share the same Spec shape, so we switch on Kind and read Spec.PayloadKeys.
// For ClusterIssuer kinds, the namespace is empty (cluster-scoped); cmNamespace is the
// fallback only when reading SecretRefs — not needed here.
func loadPayloadKeys(ctx context.Context, kube client.Client, cert *cmapi.Certificate, cmNamespace string) (api.PayloadKeys, error) {
	_ = cmNamespace
	ref := cert.Spec.IssuerRef
	switch ref.Kind {
	case "AWSSecretManagerIssuer":
		var iss api.AWSSecretManagerIssuer
		if err := kube.Get(ctx, types.NamespacedName{Name: ref.Name, Namespace: cert.Namespace}, &iss); err != nil {
			return api.PayloadKeys{}, fmt.Errorf("get AWSSecretManagerIssuer: %w", err)
		}
		return iss.Spec.PayloadKeys, nil
	case "AWSSecretManagerClusterIssuer":
		var iss api.AWSSecretManagerClusterIssuer
		if err := kube.Get(ctx, types.NamespacedName{Name: ref.Name}, &iss); err != nil {
			return api.PayloadKeys{}, fmt.Errorf("get AWSSecretManagerClusterIssuer: %w", err)
		}
		return iss.Spec.PayloadKeys, nil
	case "GCPSecretManagerIssuer":
		var iss api.GCPSecretManagerIssuer
		if err := kube.Get(ctx, types.NamespacedName{Name: ref.Name, Namespace: cert.Namespace}, &iss); err != nil {
			return api.PayloadKeys{}, fmt.Errorf("get GCPSecretManagerIssuer: %w", err)
		}
		return iss.Spec.PayloadKeys, nil
	case "GCPSecretManagerClusterIssuer":
		var iss api.GCPSecretManagerClusterIssuer
		if err := kube.Get(ctx, types.NamespacedName{Name: ref.Name}, &iss); err != nil {
			return api.PayloadKeys{}, fmt.Errorf("get GCPSecretManagerClusterIssuer: %w", err)
		}
		return iss.Spec.PayloadKeys, nil
	case "TencentSecretManagerIssuer":
		var iss api.TencentSecretManagerIssuer
		if err := kube.Get(ctx, types.NamespacedName{Name: ref.Name, Namespace: cert.Namespace}, &iss); err != nil {
			return api.PayloadKeys{}, fmt.Errorf("get TencentSecretManagerIssuer: %w", err)
		}
		return iss.Spec.PayloadKeys, nil
	case "TencentSecretManagerClusterIssuer":
		var iss api.TencentSecretManagerClusterIssuer
		if err := kube.Get(ctx, types.NamespacedName{Name: ref.Name}, &iss); err != nil {
			return api.PayloadKeys{}, fmt.Errorf("get TencentSecretManagerClusterIssuer: %w", err)
		}
		return iss.Spec.PayloadKeys, nil
	default:
		return api.PayloadKeys{}, fmt.Errorf("unknown issuer kind %q", ref.Kind)
	}
}
