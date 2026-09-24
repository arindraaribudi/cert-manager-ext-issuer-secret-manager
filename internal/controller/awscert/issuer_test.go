package awscertctrl

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/acm"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	certapi "github.com/arindraaribudi/cert-manager-ext-issuer-secret-manager/api/certificates/v1alpha1"
)

func TestReconcile_CreatesSecret(t *testing.T) {
	t.Skip("requires KUBEBUILDER_ASSETS envtest binary; see controller/setup_envtest_test.go")
}

func TestReconcile_AnnotationFilter(t *testing.T) {
	t.Skip("requires KUBEBUILDER_ASSETS envtest binary; see controller/setup_envtest_test.go")
	ctrl.SetLogger(zap.New(zap.UseDevMode(true)))
	testScheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(testScheme)
	_ = cmapi.AddToScheme(testScheme)
	_ = certapi.AddToScheme(testScheme)
	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:  testScheme,
		Metrics: metricsserver.Options{BindAddress: "0"},
	})
	if err != nil {
		t.Fatal(err)
	}
	r := &IssuerReconciler{
		Client: mgr.GetClient(),
		NewACM: func(_ context.Context, _, _ string) (*acm.Client, error) { return nil, nil },
	}
	if err := r.SetupWithManager(mgr); err != nil {
		t.Fatal(err)
	}
	_ = cmmeta.ConditionTrue
	_ = cmapi.Certificate{}
}

// TestFetch_CachesACMClientByRegionEndpoint proves NewACM is only invoked
// once for repeated Reconciles against the same (region, endpoint) pair.
// Unlike TestReconcile_CreatesSecret/AnnotationFilter above, Reconcile()
// doesn't need a running envtest manager (CertSyncer only touches
// r.Client), so this test runs against a fake client instead of skipping.
func TestFetch_CachesACMClientByRegionEndpoint(t *testing.T) {
	testScheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(testScheme)
	_ = cmapi.AddToScheme(testScheme)
	_ = certapi.AddToScheme(testScheme)

	issuer := &certapi.AWSCertificateIssuer{
		ObjectMeta: metav1.ObjectMeta{Name: "iss1", Namespace: "default"},
		Spec:       certapi.AWSCertificateIssuerSpec{Region: "us-east-1"},
	}
	cert := &cmapi.Certificate{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "c1",
			Namespace: "default",
			Annotations: map[string]string{
				AnnotationARN: "arn:aws:acm:us-east-1:123456789012:certificate/11111111-1111-1111-1111-111111111111",
			},
		},
		Spec: cmapi.CertificateSpec{
			SecretName: "c1-tls",
			IssuerRef:  cmmeta.ObjectReference{Name: "iss1", Kind: "AWSCertificateIssuer", Group: "certificates.cert-manager.io"},
		},
	}
	kube := fake.NewClientBuilder().WithScheme(testScheme).WithObjects(cert, issuer).WithStatusSubresource(&cmapi.Certificate{}).Build()

	calls := 0
	r := &IssuerReconciler{
		Client: kube,
		Scheme: testScheme,
		NewACM: func(_ context.Context, region, _ string) (*acm.Client, error) {
			calls++
			return acm.New(acm.Options{Region: region}), nil
		},
	}

	req := ctrl.Request{NamespacedName: types.NamespacedName{Name: cert.Name, Namespace: cert.Namespace}}

	if _, err := r.Reconcile(context.Background(), req); err != nil {
		t.Fatalf("first reconcile: %v", err)
	}
	if _, err := r.Reconcile(context.Background(), req); err != nil {
		t.Fatalf("second reconcile: %v", err)
	}
	if calls != 1 {
		t.Fatalf("NewACM called %d times across 2 reconciles with same region/endpoint, want 1", calls)
	}
}
