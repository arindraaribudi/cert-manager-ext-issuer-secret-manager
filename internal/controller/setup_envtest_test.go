package controller

import (
	"os"
	"testing"

	"k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	api "github.com/arindraaribudi/cert-manager-ext-issuer-secret-manager/api/v1alpha1"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
)

// TestSetupWithManagerEnvtest is a smoke test that the IssuerReconciler can be
// wired into a controller-runtime manager backed by envtest. The test is
// skipped if KUBEBUILDER_ASSETS is unset (run `setup-envtest use 1.30.x`
// locally to enable).
//
// ponytail: full E2E reconcile coverage is a follow-up; this test only proves
// the wiring compiles + registers without panic.
func TestSetupWithManagerEnvtest(t *testing.T) {
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Skip("KUBEBUILDER_ASSETS not set; run `setup-envtest use 1.30.x` first")
	}

	s := scheme.Scheme
	if err := cmapi.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	if err := api.AddToScheme(s); err != nil {
		t.Fatal(err)
	}

	env := &envtest.Environment{}
	cfg, err := env.Start()
	if err != nil {
		t.Skipf("envtest unavailable: %v", err)
	}
	defer func() { _ = env.Stop() }()

	mgr, err := ctrl.NewManager(cfg, ctrl.Options{Scheme: s})
	if err != nil {
		t.Fatal(err)
	}

	if err := ctrl.NewControllerManagedBy(mgr).
		For(&cmapi.Certificate{}).
		Complete(&IssuerReconciler{Client: mgr.GetClient(), Scheme: mgr.GetScheme()}); err != nil {
		t.Fatal(err)
	}
}
