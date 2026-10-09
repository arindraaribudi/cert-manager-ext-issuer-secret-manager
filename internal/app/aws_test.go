package app

import (
	"context"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	api "github.com/arindraaribudi/cert-manager-ext-issuer-secret-manager/api/v1alpha1"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
)

// TestAwsResolveConfig proves the AWS resolver actually reads spec.region
// and spec.SecretRef on the Issuer/ClusterIssuer, and that empty
// spec.SecretRef.Namespace falls back to the right namespace per kind.
// Replaces the earlier noop stub that returned a hardcoded error for both
// AWSSecretManagerIssuer and AWSSecretManagerClusterIssuer — if this test
// breaks, AWS certificates reconcile to SourceMissing again.
func TestAwsResolveConfig(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := api.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}

	const (
		cmNS = "cert-manager"
		issNS = "ns1"
		issName = "aws-ci"
		ciName = "aws-cluster-ci"
		credName = "aws-creds"
		credNS = "ns1"
	)

	namespaced := &api.AWSSecretManagerIssuer{
		ObjectMeta: metav1.ObjectMeta{Name: issName, Namespace: issNS},
		Spec:       api.AWSSecretManagerIssuerSpec{Region: "us-east-1"},
	}
	namespacedWithCreds := &api.AWSSecretManagerIssuer{
		ObjectMeta: metav1.ObjectMeta{Name: "with-creds", Namespace: issNS},
		Spec: api.AWSSecretManagerIssuerSpec{
			Region:    "eu-west-1",
			SecretRef: &api.SecretRef{Name: credName},
		},
	}
	clusterWide := &api.AWSSecretManagerClusterIssuer{
		ObjectMeta: metav1.ObjectMeta{Name: ciName},
		Spec: api.AWSSecretManagerIssuerSpec{
			Region: "ap-southeast-1",
			SecretRef: &api.SecretRef{
				Name:      credName,
				Namespace: credNS,
			},
		},
	}
	clusterWideDefaultNS := &api.AWSSecretManagerClusterIssuer{
		ObjectMeta: metav1.ObjectMeta{Name: "ci-default-ns"},
		Spec: api.AWSSecretManagerIssuerSpec{
			Region:    "us-west-2",
			SecretRef: &api.SecretRef{Name: credName}, // empty Namespace
		},
	}
	missingRegion := &api.AWSSecretManagerClusterIssuer{
		ObjectMeta: metav1.ObjectMeta{Name: "ci-no-region"},
		Spec:       api.AWSSecretManagerIssuerSpec{},
	}

	cli := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(
			namespaced, namespacedWithCreds,
			clusterWide, clusterWideDefaultNS, missingRegion,
		).
		Build()

	cases := []struct {
		name        string
		cert        *cmapi.Certificate
		wantRegion  string
		wantCred    string
		wantCredNS  string
		wantErrSub  string
	}{
		{
			name:       "namespaced issuer, no secretRef → default chain",
			cert:       certFor("c1", issNS, "AWSSecretManagerIssuer", issName),
			wantRegion: "us-east-1",
			wantCred:   "",
			wantCredNS: "",
		},
		{
			name:       "namespaced issuer with secretRef → ns = cert ns",
			cert:       certFor("c2", issNS, "AWSSecretManagerIssuer", "with-creds"),
			wantRegion: "eu-west-1",
			wantCred:   credName,
			wantCredNS: issNS,
		},
		{
			name:       "cluster issuer, secretRef has ns → ns preserved",
			cert:       certFor("c3", issNS, "AWSSecretManagerClusterIssuer", ciName),
			wantRegion: "ap-southeast-1",
			wantCred:   credName,
			wantCredNS: credNS,
		},
		{
			name:       "cluster issuer, secretRef ns empty → fall back to cm namespace",
			cert:       certFor("c4", issNS, "AWSSecretManagerClusterIssuer", "ci-default-ns"),
			wantRegion: "us-west-2",
			wantCred:   credName,
			wantCredNS: cmNS,
		},
		{
			name:       "missing region → error",
			cert:       certFor("c5", issNS, "AWSSecretManagerClusterIssuer", "ci-no-region"),
			wantErrSub: "missing spec.region",
		},
		{
			name:       "unknown kind → error",
			cert:       certFor("c6", issNS, "AWSSecretManagerIssuer", "does-not-exist"),
			wantErrSub: "AWSSecretManagerIssuer",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			region, credName, credNS, _, err := awsResolveConfig(context.Background(), cli, tc.cert, cmNS)
			if tc.wantErrSub != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tc.wantErrSub)
				}
				if !contains(err.Error(), tc.wantErrSub) {
					t.Fatalf("error = %q, want substring %q", err.Error(), tc.wantErrSub)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if region != tc.wantRegion {
				t.Errorf("region = %q, want %q", region, tc.wantRegion)
			}
			if credName != tc.wantCred {
				t.Errorf("credName = %q, want %q", credName, tc.wantCred)
			}
			if credNS != tc.wantCredNS {
				t.Errorf("credNS = %q, want %q", credNS, tc.wantCredNS)
			}
		})
	}
}

func certFor(name, ns, kind, issuerName string) *cmapi.Certificate {
	return &cmapi.Certificate{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Spec: cmapi.CertificateSpec{
			IssuerRef: cmmeta.ObjectReference{
				Name: issuerName,
				Kind: kind,
			},
		},
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
