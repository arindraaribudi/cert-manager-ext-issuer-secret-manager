// Package tencent wraps Tencent Cloud SSL behind a Fetch interface.
// ponytail: full SDK wiring deferred (returns AuthFailed). Follow-up task
// lifts ssl.go patterns from reference repo (cert-manager-ext-issuer-tencent).
package tencent

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	corev1 "k8s.io/api/core/v1"

	api "github.com/arindraaribudi/cert-manager-ext-issuer-secret-manager/api/v1alpha1"
)

// New is a stub. The real implementation will build a Tencent SSL SDK client
// from static creds (via creds from a k8s Secret) or pod identity chain.
// Today it always returns an error so callers fail loudly if invoked without
// the fake.
func New(ctx context.Context, region string, creds *api.SecretRef, kube client.Client) (string, error) {
	_ = ctx
	_ = region
	_ = creds
	_ = kube
	return "", fmt.Errorf("tencent: real SDK wiring not yet implemented (use fake for tests)")
}

// LoadStaticCredentials resolves a Tencent SecretRef to (secretID, secretKey).
// ponytail: stub today; full impl lifted from reference repo later.
func LoadStaticCredentials(ctx context.Context, c client.Client, name, namespace string) (string, string, error) {
	_ = ctx
	var s corev1.Secret
	if err := c.Get(ctx, types.NamespacedName{Name: name, Namespace: namespace}, &s); err != nil {
		return "", "", fmt.Errorf("tencent: get secret: %w", err)
	}
	return string(s.Data["secret-id"]), string(s.Data["secret-key"]), nil
}
