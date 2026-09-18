package awscertctrl

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/acm"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"

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