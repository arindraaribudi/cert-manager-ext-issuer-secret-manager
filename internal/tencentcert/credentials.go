// Package tencentcert credentials: SDK chain (TKE OIDC → env → CVM role)
// via common.NewProviderChain. ponytail: SDK ships all three providers;
// the chain is the only thing we add. Matches reference repo pattern.
package tencentcert

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	tccommon "github.com/tencentcloud/tencentcloud-sdk-go-intl-en/tencentcloud/common"
)

// LoadStaticCredentials returns (secret-id, secret-key) from a k8s Secret.
// ponytail: named after Tencent SDK env vars (TENCENTCLOUD_SECRET_ID/KEY)
// so users reuse the same Secret format they already know.
func LoadStaticCredentials(ctx context.Context, c client.Client, name, namespace string) (string, string, error) {
	var s corev1.Secret
	if err := c.Get(ctx, client.ObjectKey{Name: name, Namespace: namespace}, &s); err != nil {
		return "", "", fmt.Errorf("tencentcert: get secret: %w", err)
	}
	id := string(s.Data["secret-id"])
	key := string(s.Data["secret-key"])
	if id == "" || key == "" {
		return "", "", fmt.Errorf("tencentcert: secret %s/%s missing secret-id or secret-key", namespace, name)
	}
	return id, key, nil
}

// BuildCredentialProvider resolves credentials from the SDK chain:
// TKE OIDC pod-identity → env vars → CVM instance metadata.
func BuildCredentialProvider(ctx context.Context) (tccommon.CredentialIface, error) {
	var providers []tccommon.Provider
	if p, err := tccommon.DefaultTkeOIDCRoleArnProvider(); err == nil {
		providers = append(providers, p)
	}
	providers = append(providers, tccommon.DefaultEnvProvider())
	providers = append(providers, tccommon.DefaultCvmRoleProvider())
	cred, err := tccommon.NewProviderChain(providers).GetCredential()
	if err != nil {
		return nil, fmt.Errorf("tencentcert: credential chain exhausted: %w", err)
	}
	return cred, nil
}
