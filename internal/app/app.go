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
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"

	api "github.com/arindraaribudi/cert-manager-ext-issuer-secret-manager/api/v1alpha1"
	certapi "github.com/arindraaribudi/cert-manager-ext-issuer-secret-manager/api/certificates/v1alpha1"
	"github.com/arindraaribudi/cert-manager-ext-issuer-secret-manager/internal/aws"
	awscertpkg "github.com/arindraaribudi/cert-manager-ext-issuer-secret-manager/internal/awscert"
	"github.com/arindraaribudi/cert-manager-ext-issuer-secret-manager/internal/controller"
	awscertctrl "github.com/arindraaribudi/cert-manager-ext-issuer-secret-manager/internal/controller/awscert"
	"github.com/arindraaribudi/cert-manager-ext-issuer-secret-manager/internal/controller/casource"
	tencentcertctrl "github.com/arindraaribudi/cert-manager-ext-issuer-secret-manager/internal/controller/tencentcert"
	"github.com/arindraaribudi/cert-manager-ext-issuer-secret-manager/internal/gcp"
	"github.com/arindraaribudi/cert-manager-ext-issuer-secret-manager/internal/tencentcert"

	"github.com/aws/aws-sdk-go-v2/service/acm"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	tccommon "github.com/tencentcloud/tencentcloud-sdk-go-intl-en/tencentcloud/common"
	tcprofile "github.com/tencentcloud/tencentcloud-sdk-go-intl-en/tencentcloud/common/profile"
	tcssl "github.com/tencentcloud/tencentcloud-sdk-go-intl-en/tencentcloud/ssl/v20191205"
	tcssm "github.com/tencentcloud/tencentcloud-sdk-go-intl-en/tencentcloud/ssm/v20190923"

	"github.com/arindraaribudi/cert-manager-ext-issuer-secret-manager/internal/tencent"
)

// ourIssuerFilter drops every Certificate event whose IssuerRef.Group isn't
// ours. Without this the controller wakes up for every cert-manager cert in
// the cluster (Let’s Encrypt, self-signed, etc.) and does a useless Get +
// lookupResolver miss on each. ponytail: matches controller.IssuerGroup
// single source of truth — keep the two in step.
func ourIssuerFilter() predicate.Funcs {
	isOurs := func(o client.Object) bool {
		c, ok := o.(*cmapi.Certificate)
		return ok && c.Spec.IssuerRef.Group == controller.IssuerGroup
	}
	return predicate.Funcs{
		CreateFunc: func(e event.CreateEvent) bool { return isOurs(e.Object) },
		UpdateFunc: func(e event.UpdateEvent) bool { return isOurs(e.ObjectNew) },
		DeleteFunc:  func(e event.DeleteEvent) bool { return false }, // nothing to do on delete
		GenericFunc: func(e event.GenericEvent) bool { return isOurs(e.Object) },
	}
}

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
	utilruntime.Must(certapi.AddToScheme(s))
	return s
}

// BuildIssuerResolvers creates the per-Issuer-kind SecretResolver closures
// and the PayloadKeysFromIssuer callback. Each closure captures the right
// cloud SDK client for its provider. Resolvers cache clients per region/project
// (cheap; SDK clients are safe for concurrent use).
func BuildIssuerResolvers(ctx context.Context, kube client.Client, cmNamespace string) (map[string]controller.SecretResolver, func(ctx context.Context, cert *cmapi.Certificate) (api.IssuerConfig, error)) {
	resolvers := map[string]controller.SecretResolver{}

	// AWS resolvers — both Issuer + ClusterIssuer kinds share the same closure.
	resolvers["AWSSecretManagerIssuer"] = awsResolver(ctx, kube, cmNamespace)
	resolvers["AWSSecretManagerClusterIssuer"] = resolvers["AWSSecretManagerIssuer"]

	// GCP
	resolvers["GCPSecretManagerIssuer"] = gcpResolver(ctx, kube, cmNamespace)
	resolvers["GCPSecretManagerClusterIssuer"] = resolvers["GCPSecretManagerIssuer"]

	// Tencent — real SSM client, cached per (region, creds, endpoint).
	resolvers["TencentSecretManagerIssuer"] = tencentResolver(ctx, kube, cmNamespace)
	resolvers["TencentSecretManagerClusterIssuer"] = resolvers["TencentSecretManagerIssuer"]

	cfgFn := func(ctx context.Context, cert *cmapi.Certificate) (api.IssuerConfig, error) {
		return loadIssuerConfig(ctx, kube, cert, cmNamespace)
	}
	return resolvers, cfgFn
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

	resolvers, cfgFn := BuildIssuerResolvers(ctx, mgr.GetClient(), opts.CertManagerNamespace)

	reconciler := &controller.IssuerReconciler{
		Client:                  mgr.GetClient(),
		Scheme:                  mgr.GetScheme(),
		ProviderResolvers:       resolvers,
		IssuerConfigFromIssuer:  cfgFn,
		CertManagerNamespace:    opts.CertManagerNamespace,
	}

	if err := ctrl.NewControllerManagedBy(mgr).
		For(&cmapi.Certificate{}, builder.WithPredicates(ourIssuerFilter())).
		Complete(reconciler); err != nil {
		return fmt.Errorf("build controller: %w", err)
	}

	awsCertRec := &awscertctrl.IssuerReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
		NewACM: newACMClient,
	}
	if err := awsCertRec.SetupWithManager(mgr); err != nil {
		return fmt.Errorf("setup awscert controller: %w", err)
	}

	tcCertRec := &tencentcertctrl.IssuerReconciler{
		Client:       mgr.GetClient(),
		Scheme:       mgr.GetScheme(),
		NewSSLClient: newTencentSSLClient,
	}
	if err := tcCertRec.SetupWithManager(mgr); err != nil {
		return fmt.Errorf("setup tencentcert controller: %w", err)
	}

	// CASource controllers — trust-manager CA bundles from cloud SM.
	awsCASrc := &casource.AWSReconciler{
		Reconciler: &casource.Reconciler{
			Client: mgr.GetClient(),
			Prefix: "aws",
			Fetch:  casource.NewAWSFetch(mgr.GetClient(), opts.CertManagerNamespace),
		},
	}
	if err := awsCASrc.SetupWithManager(mgr); err != nil {
		return fmt.Errorf("setup awscasource controller: %w", err)
	}

	gcpCASrc := &casource.GCPReconciler{
		Reconciler: &casource.Reconciler{
			Client: mgr.GetClient(),
			Prefix: "gcp",
			Fetch:  casource.NewGCPFetch(),
		},
	}
	if err := gcpCASrc.SetupWithManager(mgr); err != nil {
		return fmt.Errorf("setup gcpcasource controller: %w", err)
	}

	tcCASrc := &casource.TencentReconciler{
		Reconciler: &casource.Reconciler{
			Client: mgr.GetClient(),
			Prefix: "tencent",
			Fetch:  casource.NewTencentFetch(mgr.GetClient(), opts.CertManagerNamespace),
		},
	}
	if err := tcCASrc.SetupWithManager(mgr); err != nil {
		return fmt.Errorf("setup tencentcasource controller: %w", err)
	}

	if err := mgr.Add(&controller.Resyncer{
		Client:    mgr.GetClient(),
		Reconcile: reconciler.Reconcile,
		Interval:  opts.ResyncInterval,
	}); err != nil {
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

// awsResolver returns a SecretResolver that fetches issued certs from
// AWS Secrets Manager. Default-chain clients (IRSA / env / EC2) are cached
// per region; static-creds clients (spec.SecretRef with AK/SK keys) are
// rebuilt per call — the SDK constructor is microseconds and avoids a
// composite cache key.
func awsResolver(ctx context.Context, kube client.Client, cmNamespace string) controller.SecretResolver {
	var mu sync.Mutex
	cache := map[string]*secretsmanager.Client{}
	_ = ctx
	// newClient returns a Secrets Manager client honouring spec.Endpoint
	// (VPC endpoint / LocalStack / non-AWS compatible). Empty endpoint
	// keeps SDK's region-based default resolution.
	newClient := func(callCtx context.Context, region, endpoint string) (*secretsmanager.Client, error) {
		cfg, err := awscertpkg.BuildCredentialConfig(callCtx, region)
		if err != nil {
			return nil, fmt.Errorf("aws: load default config for region %q: %w", region, err)
		}
		if endpoint != "" {
			ep := endpoint
			cfg.BaseEndpoint = &ep
		}
		return secretsmanager.NewFromConfig(cfg), nil
	}
	clientFor := func(callCtx context.Context, region, credName, credNS, endpoint string) (*secretsmanager.Client, error) {
		key := region + "|" + endpoint
		if credName == "" {
			mu.Lock()
			defer mu.Unlock()
			if c, ok := cache[key]; ok {
				return c, nil
			}
			c, err := newClient(callCtx, region, endpoint)
			if err != nil {
				return nil, err
			}
			cache[key] = c
			return c, nil
		}
		cfg, err := awscertpkg.LoadStaticCredentials(callCtx, kube, credName, credNS)
		if err != nil {
			return nil, fmt.Errorf("aws: load static creds from secret %s/%s: %w", credNS, credName, err)
		}
		// ponytail: SDK requires the region even when only Creds are overridden;
		// LoadStaticCredentials already pins WithRegion via BuildCredentialConfig's
		// default — but the default uses the chain's region, which may be unset
		// when creds come from a static AK/SK pair. Re-pin to the issuer region.
		cfg.Region = region
		if endpoint != "" {
			ep := endpoint
			cfg.BaseEndpoint = &ep
		}
		return secretsmanager.NewFromConfig(cfg), nil
	}
	return func(callCtx context.Context, cert *cmapi.Certificate) ([]byte, error) {
		ref, ok := controller.SecretName(cert)
		if !ok {
			return nil, fmt.Errorf("aws: certificate %s/%s missing annotation %s", cert.Namespace, cert.Name, controller.AnnotationSecretName)
		}
		region, credName, credNS, endpoint, err := awsResolveConfig(callCtx, kube, cert, cmNamespace)
		if err != nil {
			return nil, err
		}
		cli, err := clientFor(callCtx, region, credName, credNS, endpoint)
		if err != nil {
			return nil, err
		}
		return aws.Wrap(cli).Fetch(callCtx, ref)
	}
}

// awsResolveConfig looks up the Issuer/ClusterIssuer for cert, returns
// (region, credentialSecretName, credentialSecretNamespace). Credentials
// default to the SDK chain (IRSA / env / EC2) when spec.SecretRef is nil;
// otherwise the named Secret must carry access-key-id + secret-access-key.
// Empty spec.SecretRef.Namespace falls back to cert.Namespace (Issuer) or
// cmNamespace (ClusterIssuer).
func awsResolveConfig(ctx context.Context, kube client.Client, cert *cmapi.Certificate, cmNamespace string) (region, credName, credNS, endpoint string, err error) {
	ref := cert.Spec.IssuerRef
	var region2, endpoint2 string
	var sref *api.SecretRef
	switch ref.Kind {
	case "AWSSecretManagerIssuer":
		var iss api.AWSSecretManagerIssuer
		if err := kube.Get(ctx, types.NamespacedName{Name: ref.Name, Namespace: cert.Namespace}, &iss); err != nil {
			return "", "", "", "", fmt.Errorf("aws: get AWSSecretManagerIssuer %s/%s: %w", cert.Namespace, ref.Name, err)
		}
		region2, endpoint2, sref = iss.Spec.Region, iss.Spec.Endpoint, iss.Spec.SecretRef
	case "AWSSecretManagerClusterIssuer":
		var iss api.AWSSecretManagerClusterIssuer
		if err := kube.Get(ctx, types.NamespacedName{Name: ref.Name}, &iss); err != nil {
			return "", "", "", "", fmt.Errorf("aws: get AWSSecretManagerClusterIssuer %s: %w", ref.Name, err)
		}
		region2, endpoint2, sref = iss.Spec.Region, iss.Spec.Endpoint, iss.Spec.SecretRef
	default:
		return "", "", "", "", fmt.Errorf("aws: unexpected issuer kind %q", ref.Kind)
	}
	if region2 == "" {
		return "", "", "", "", fmt.Errorf("aws: issuer %s/%s missing spec.region", ref.Kind, ref.Name)
	}
	credName2, credNS2 := "", ""
	if sref != nil {
		credName2 = sref.Name
		credNS2 = sref.Namespace
		if credNS2 == "" {
			switch ref.Kind {
			case "AWSSecretManagerIssuer":
				credNS2 = cert.Namespace
			case "AWSSecretManagerClusterIssuer":
				credNS2 = cmNamespace
			}
		}
	}
	return region2, credName2, credNS2, endpoint2, nil
}

// gcpResolver returns a SecretResolver that fetches issued certs from
// GCP Secret Manager. Reads the issuer spec per call so spec.Endpoint
// (VPC-SC / Private Google Access / non-GCP test target) is honoured
// per-issuer. Per-call client construction is cheap and avoids a
// (project × endpoint) cache key the bootstrap-once model would need.
func gcpResolver(ctx context.Context, kube client.Client, _ string) controller.SecretResolver {
	_ = ctx
	return func(callCtx context.Context, cert *cmapi.Certificate) ([]byte, error) {
		ref, ok := controller.SecretName(cert)
		if !ok {
			return nil, fmt.Errorf("gcp: certificate %s/%s missing annotation %s", cert.Namespace, cert.Name, controller.AnnotationSecretName)
		}
		endpoint, err := gcpResolveConfig(callCtx, kube, cert)
		if err != nil {
			return nil, err
		}
		// ponytail: nil adcJSON → Workload Identity / ADC chain. Static
		// ADC JSON is not exposed yet (spec.SecretRef unused for GCP);
		// add when a user asks.
		cli, err := gcp.New(callCtx, nil, endpoint)
		if err != nil {
			return nil, fmt.Errorf("gcp: new client: %w", err)
		}
		return gcp.Fetch(callCtx, cli, normalizeGCPVersion(ref))
	}
}

// gcpResolveConfig looks up the GCP Issuer/ClusterIssuer and returns
// spec.Endpoint.
func gcpResolveConfig(ctx context.Context, kube client.Client, cert *cmapi.Certificate) (endpoint string, err error) {
	ref := cert.Spec.IssuerRef
	switch ref.Kind {
	case "GCPSecretManagerIssuer":
		var iss api.GCPSecretManagerIssuer
		if err := kube.Get(ctx, types.NamespacedName{Name: ref.Name, Namespace: cert.Namespace}, &iss); err != nil {
			return "", fmt.Errorf("gcp: get GCPSecretManagerIssuer %s/%s: %w", cert.Namespace, ref.Name, err)
		}
		return iss.Spec.Endpoint, nil
	case "GCPSecretManagerClusterIssuer":
		var iss api.GCPSecretManagerClusterIssuer
		if err := kube.Get(ctx, types.NamespacedName{Name: ref.Name}, &iss); err != nil {
			return "", fmt.Errorf("gcp: get GCPSecretManagerClusterIssuer %s: %w", ref.Name, err)
		}
		return iss.Spec.Endpoint, nil
	default:
		return "", fmt.Errorf("gcp: unexpected issuer kind %q", ref.Kind)
	}
}

// tencentResolver returns a SecretResolver that fetches issued certs from
// Tencent SSM. SDK clients are cached per region — the OIDC provider
// handles STS token refresh internally, so caching by region (not creds)
// keeps a single client per region across all certs. Closure captures
// the kube client + cert-manager namespace fallback for empty
// spec.SecretRef.Namespace on ClusterIssuer kinds.
func tencentResolver(ctx context.Context, kube client.Client, cmNamespace string) controller.SecretResolver {
	var mu sync.Mutex
	cache := map[string]*tcssm.Client{}
	_ = ctx
	clientFor := func(callCtx context.Context, region, endpoint string, cred tccommon.CredentialIface) (*tcssm.Client, error) {
		key := region + "|" + endpoint
		mu.Lock()
		defer mu.Unlock()
		if c, ok := cache[key]; ok {
			return c, nil
		}
		c, err := tencent.New(callCtx, region, cred, endpoint)
		if err != nil {
			return nil, err
		}
		cache[key] = c
		return c, nil
	}
	return func(callCtx context.Context, cert *cmapi.Certificate) ([]byte, error) {
		ref, ok := controller.SecretName(cert)
		if !ok {
			return nil, fmt.Errorf("tencent: certificate %s/%s missing annotation %s", cert.Namespace, cert.Name, controller.AnnotationSecretName)
		}
		region, endpoint, cred, err := tencentResolveConfig(callCtx, kube, cert, cmNamespace)
		if err != nil {
			return nil, err
		}
		c, err := clientFor(callCtx, region, endpoint, cred)
		if err != nil {
			return nil, err
		}
		return tencent.Fetch(callCtx, c, ref)
	}
}

// tencentResolveConfig looks up the Issuer/ClusterIssuer for cert, returns
// (region, credential). Credential resolution: TKE OIDC pod identity
// (when env is bound) → static AK/SK from spec.secretRef. Endpoint is
// empty → SDK defaults to public. Empty spec.SecretRef.Namespace falls
// back to cert.Namespace (Issuer) or cmNamespace (ClusterIssuer).
func tencentResolveConfig(ctx context.Context, kube client.Client, cert *cmapi.Certificate, cmNamespace string) (region, endpoint string, cred tccommon.CredentialIface, err error) {
	ref := cert.Spec.IssuerRef
	var region2, endpoint2 string
	var sref *api.SecretRef
	switch ref.Kind {
	case "TencentSecretManagerIssuer":
		var iss api.TencentSecretManagerIssuer
		if err := kube.Get(ctx, types.NamespacedName{Name: ref.Name, Namespace: cert.Namespace}, &iss); err != nil {
			return "", "", nil, fmt.Errorf("tencent: get TencentSecretManagerIssuer %s/%s: %w", cert.Namespace, ref.Name, err)
		}
		region2, endpoint2, sref = iss.Spec.Region, iss.Spec.Endpoint, iss.Spec.SecretRef
	case "TencentSecretManagerClusterIssuer":
		var iss api.TencentSecretManagerClusterIssuer
		if err := kube.Get(ctx, types.NamespacedName{Name: ref.Name}, &iss); err != nil {
			return "", "", nil, fmt.Errorf("tencent: get TencentSecretManagerClusterIssuer %s: %w", ref.Name, err)
		}
		region2, endpoint2, sref = iss.Spec.Region, iss.Spec.Endpoint, iss.Spec.SecretRef
	default:
		return "", "", nil, fmt.Errorf("tencent: unexpected issuer kind %q", ref.Kind)
	}
	if region2 == "" {
		return "", "", nil, fmt.Errorf("tencent: issuer %s/%s missing spec.region", ref.Kind, ref.Name)
	}
	// TKE OIDC wins when the pod is on TKE; secretRef becomes optional.
	credName, credNS := "", ""
	if sref != nil {
		credName = sref.Name
		credNS = sref.Namespace
		if credNS == "" {
			switch ref.Kind {
			case "TencentSecretManagerIssuer":
				credNS = cert.Namespace
			case "TencentSecretManagerClusterIssuer":
				credNS = cmNamespace
			}
		}
	}
	cred, err = tencent.ResolveCredential(ctx, kube, credName, credNS)
	if err != nil {
		return "", "", nil, err
	}
	return region2, endpoint2, cred, nil
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

// loadIssuerConfig reads the Issuer referenced by cert and returns its
// PayloadKeys + NamespaceFilter. All 6 kinds share the same Spec shape, so
// we switch on Kind and read Spec. For ClusterIssuer kinds, the namespace is
// empty (cluster-scoped); cmNamespace is the fallback only when reading
// SecretRefs — not needed here.
func loadIssuerConfig(ctx context.Context, kube client.Client, cert *cmapi.Certificate, cmNamespace string) (api.IssuerConfig, error) {
	_ = cmNamespace
	ref := cert.Spec.IssuerRef
	switch ref.Kind {
	case "AWSSecretManagerIssuer":
		var iss api.AWSSecretManagerIssuer
		if err := kube.Get(ctx, types.NamespacedName{Name: ref.Name, Namespace: cert.Namespace}, &iss); err != nil {
			return api.IssuerConfig{}, fmt.Errorf("get AWSSecretManagerIssuer: %w", err)
		}
		return api.IssuerConfig{PayloadKeys: iss.Spec.PayloadKeys, NamespaceFilter: iss.Spec.NamespaceFilter}, nil
	case "AWSSecretManagerClusterIssuer":
		var iss api.AWSSecretManagerClusterIssuer
		if err := kube.Get(ctx, types.NamespacedName{Name: ref.Name}, &iss); err != nil {
			return api.IssuerConfig{}, fmt.Errorf("get AWSSecretManagerClusterIssuer: %w", err)
		}
		return api.IssuerConfig{PayloadKeys: iss.Spec.PayloadKeys, NamespaceFilter: iss.Spec.NamespaceFilter}, nil
	case "GCPSecretManagerIssuer":
		var iss api.GCPSecretManagerIssuer
		if err := kube.Get(ctx, types.NamespacedName{Name: ref.Name, Namespace: cert.Namespace}, &iss); err != nil {
			return api.IssuerConfig{}, fmt.Errorf("get GCPSecretManagerIssuer: %w", err)
		}
		return api.IssuerConfig{PayloadKeys: iss.Spec.PayloadKeys, NamespaceFilter: iss.Spec.NamespaceFilter}, nil
	case "GCPSecretManagerClusterIssuer":
		var iss api.GCPSecretManagerClusterIssuer
		if err := kube.Get(ctx, types.NamespacedName{Name: ref.Name}, &iss); err != nil {
			return api.IssuerConfig{}, fmt.Errorf("get GCPSecretManagerClusterIssuer: %w", err)
		}
		return api.IssuerConfig{PayloadKeys: iss.Spec.PayloadKeys, NamespaceFilter: iss.Spec.NamespaceFilter}, nil
	case "TencentSecretManagerIssuer":
		var iss api.TencentSecretManagerIssuer
		if err := kube.Get(ctx, types.NamespacedName{Name: ref.Name, Namespace: cert.Namespace}, &iss); err != nil {
			return api.IssuerConfig{}, fmt.Errorf("get TencentSecretManagerIssuer: %w", err)
		}
		return api.IssuerConfig{PayloadKeys: iss.Spec.PayloadKeys, NamespaceFilter: iss.Spec.NamespaceFilter}, nil
	case "TencentSecretManagerClusterIssuer":
		var iss api.TencentSecretManagerClusterIssuer
		if err := kube.Get(ctx, types.NamespacedName{Name: ref.Name}, &iss); err != nil {
			return api.IssuerConfig{}, fmt.Errorf("get TencentSecretManagerClusterIssuer: %w", err)
		}
		return api.IssuerConfig{PayloadKeys: iss.Spec.PayloadKeys, NamespaceFilter: iss.Spec.NamespaceFilter}, nil
	default:
		return api.IssuerConfig{}, fmt.Errorf("unknown issuer kind %q", ref.Kind)
	}
}

// newACMClient builds an AWS ACM client. Region comes from the Issuer spec;
// optional endpoint override supports VPC endpoint testing. Ponytail:
// credential chain (IRSA / env / EC2) is the SDK's default — no custom
// plumbing needed here.
func newACMClient(ctx context.Context, region, endpoint string) (*acm.Client, error) {
	cfg, err := awscertpkg.BuildCredentialConfig(ctx, region)
	if err != nil {
		return nil, err
	}
	if endpoint != "" {
		cfg.BaseEndpoint = &endpoint
	}
	return acm.NewFromConfig(cfg), nil
}

// newTencentSSLClient builds a Tencent SSL client. Endpoint defaults to the
// public ssl.tencentcloudapi.com; spec.Endpoint can override for testing.
func newTencentSSLClient(creds tccommon.CredentialIface, region, endpoint string) (*tencentcert.SSLClient, error) {
	if endpoint == "" {
		endpoint = "ssl.tencentcloudapi.com"
	}
	prof := tcprofile.NewClientProfile()
	prof.HttpProfile.Endpoint = endpoint
	cli, err := tcssl.NewClient(creds, region, prof)
	if err != nil {
		return nil, err
	}
	return tencentcert.New(cli), nil
}
