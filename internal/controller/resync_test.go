package controller

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	api "github.com/arindraaribudi/cert-manager-ext-issuer-secret-manager/api/v1alpha1"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
)

func TestHash(t *testing.T) {
	got := Hash([]byte("hello"))
	if got == "" {
		t.Fatal("hash should not be empty")
	}
	// Deterministic
	if got != Hash([]byte("hello")) {
		t.Fatal("hash should be deterministic")
	}
	// Different input -> different hash
	if got == Hash([]byte("world")) {
		t.Fatal("different inputs should produce different hashes")
	}
}

func TestHash_Empty(t *testing.T) {
	if Hash([]byte{}) != "" {
		t.Fatal("empty input should produce empty hash")
	}
}

// TestResyncer_Drift verifies the drift tick:
// - lists Certificates
// - calls Reconcile only for our IssuerRef.Group
// - tolerates errors per cert (one bad cert doesn't abort the loop)
func TestResyncer_Drift(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := cmapi.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}

	// ours (group matches) — must be reconciled
	ours := &cmapi.Certificate{
		ObjectMeta: metav1.ObjectMeta{Name: "ours", Namespace: "ns1"},
		Spec: cmapi.CertificateSpec{
			IssuerRef: cmmeta.ObjectReference{Name: "x", Kind: "K", Group: IssuerGroup},
		},
	}
	// not ours — must be skipped
	theirs := &cmapi.Certificate{
		ObjectMeta: metav1.ObjectMeta{Name: "theirs", Namespace: "ns1"},
		Spec: cmapi.CertificateSpec{
			IssuerRef: cmmeta.ObjectReference{Name: "y", Kind: "Issuer", Group: "cert-manager.io"},
		},
	}
	// ours but reconcile will return error — must not abort
	bad := &cmapi.Certificate{
		ObjectMeta: metav1.ObjectMeta{Name: "bad", Namespace: "ns1"},
		Spec: cmapi.CertificateSpec{
			IssuerRef: cmmeta.ObjectReference{Name: "z", Kind: "K", Group: IssuerGroup},
		},
	}

	cli := fake.NewClientBuilder().WithScheme(scheme).WithObjects(ours, theirs, bad).Build()

	var mu sync.Mutex
	got := map[types.NamespacedName]int{}
	r := &Resyncer{
		Client: cli,
		Reconcile: func(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
			mu.Lock()
			got[req.NamespacedName]++
			mu.Unlock()
			if req.Name == "bad" {
				return ctrl.Result{}, context.DeadlineExceeded
			}
			return ctrl.Result{}, nil
		},
	}

	r.drift(context.Background())

	if got[client.ObjectKeyFromObject(ours)] != 1 {
		t.Errorf("ours not reconciled: %v", got)
	}
	if _, ok := got[client.ObjectKeyFromObject(theirs)]; ok {
		t.Errorf("theirs must be skipped, got reconciled: %v", got)
	}
	if got[client.ObjectKeyFromObject(bad)] != 1 {
		t.Errorf("bad cert must still be reconciled despite error: %v", got)
	}
}

// TestResyncer_StartDisabled verifies Interval<=0 keeps the Runnable alive
// on ctx without ticking. ponytail: matches the no-tick test contract used
// in envtest setups where the ticker is suppressed.
func TestResyncer_StartDisabled(t *testing.T) {
	r := &Resyncer{
		Client:    fake.NewClientBuilder().Build(),
		Reconcile: func(context.Context, ctrl.Request) (ctrl.Result, error) { return ctrl.Result{}, nil },
		Interval:  0,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := r.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
}

// TestResyncer_Drift_ReconcilesAllCertsConcurrently verifies drift() fans out
// reconciles through the bounded errgroup pool and every matching cert gets
// reconciled exactly once. Run with -race to prove the pool has no data races.
func TestResyncer_Drift_ReconcilesAllCertsConcurrently(t *testing.T) {
	s := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	if err := cmapi.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	var objs []client.Object
	const n = 25
	for i := 0; i < n; i++ {
		objs = append(objs, &cmapi.Certificate{
			ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("c%d", i), Namespace: "default"},
			Spec:       cmapi.CertificateSpec{IssuerRef: cmmeta.ObjectReference{Group: IssuerGroup}},
		})
	}
	kube := fake.NewClientBuilder().WithScheme(s).WithObjects(objs...).Build()

	var reconciled int64
	r := &Resyncer{
		Client:   kube,
		Interval: 10 * time.Millisecond,
		Reconcile: func(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
			atomic.AddInt64(&reconciled, 1)
			return ctrl.Result{}, nil
		},
	}
	r.drift(context.Background())
	if got := atomic.LoadInt64(&reconciled); got != n {
		t.Fatalf("reconciled %d certs, want %d", got, n)
	}
}

// Reference to keep api import alive (used elsewhere too)
var _ = api.SecretRef{}
