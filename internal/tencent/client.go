// Package tencent wraps Tencent Cloud SSM behind a SecretResolver.
// Provides New (builds a real SSM client) + Fetch (reads a secret's
// plaintext). Real implementation; LoadStaticCredentials resolves the k8s
// Secret holding TENCENTCLOUD_SECRET_ID/KEY data the same way the SSL
// controller does. Pod identity (TKE OIDC) supported via ResolveCredential
// — preferred when the pod is running on TKE with the right env, otherwise
// falls back to the static AK/SK in spec.secretRef.
package tencent

import (
	"context"
	"fmt"
	"os"

	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	corev1 "k8s.io/api/core/v1"

	tccommon "github.com/tencentcloud/tencentcloud-sdk-go-intl-en/tencentcloud/common"
	tcprofile "github.com/tencentcloud/tencentcloud-sdk-go-intl-en/tencentcloud/common/profile"
	tcssm "github.com/tencentcloud/tencentcloud-sdk-go-intl-en/tencentcloud/ssm/v20190923"
)

// New builds a Tencent SSM SDK client. Endpoint "" → ssm.intl.tencentcloudapi.com
// (the intl-en SDK's home partition; matches tccli for intl accounts).
// CN users can override with `ssm.tencentcloudapi.com` via the issuer spec.
// cred is any common.CredentialIface — static, TKE OIDC, or chained.
func New(ctx context.Context, region string, cred tccommon.CredentialIface, endpoint string) (*tcssm.Client, error) {
	if region == "" {
		return nil, fmt.Errorf("tencent: region required")
	}
	if cred == nil {
		return nil, fmt.Errorf("tencent: credential required")
	}
	if endpoint == "" {
		endpoint = "ssm.intl.tencentcloudapi.com"
	}
	prof := tcprofile.NewClientProfile()
	prof.HttpProfile.Endpoint = endpoint
	return tcssm.NewClient(cred, region, prof)
}

// Fetch reads the currently-staged version of secretName and returns its
// plaintext SecretString. Works for v1, v6, anything in between. Errors
// when the secret is binary-only (no SecretString), missing, or the API
// call fails. ponytail: the intl-en partition rejects the "SSM_Current"
// sentinel string in VersionId, so we resolve the numeric id via
// ListSecretVersionIds first — works on every version (1, 6, …).
func Fetch(ctx context.Context, c *tcssm.Client, secretName string) ([]byte, error) {
	vid, err := currentVersion(ctx, c, secretName)
	if err != nil {
		return nil, fmt.Errorf("tencent: resolve current version of %q: %w", secretName, err)
	}
	req := tcssm.NewGetSecretValueRequest()
	req.SecretName = &secretName
	req.VersionId = &vid
	resp, err := c.GetSecretValueWithContext(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("tencent: get secret %q: %w", secretName, err)
	}
	if resp.Response == nil {
		return nil, fmt.Errorf("tencent: nil response for %q", secretName)
	}
	if resp.Response.SecretString == nil {
		return nil, fmt.Errorf("tencent: secret %q is binary-only (no SecretString); payloadKeys extract not applicable", secretName)
	}
	return []byte(*resp.Response.SecretString), nil
}

// currentVersion returns the highest numeric VersionId for secretName
// (TC SSM versions are monotonic integers; latest = largest). The intl-en
// SDK's VersionInfo exposes only VersionId+CreateTime (no VersionStages),
// so the SSM_Current/SSM_Previous stage labels aren't reachable here.
// Errors when the secret has no versions or no numeric id.
// ponytail: global ceiling — one ListSecretVersionIds call per Fetch.
// Add a short-TTL cache in tencentResolver when rotation traffic matters.
func currentVersion(ctx context.Context, c *tcssm.Client, secretName string) (string, error) {
	req := tcssm.NewListSecretVersionIdsRequest()
	req.SecretName = &secretName
	resp, err := c.ListSecretVersionIdsWithContext(ctx, req)
	if err != nil {
		return "", err
	}
	if resp.Response == nil || len(resp.Response.Versions) == 0 {
		return "", fmt.Errorf("no versions")
	}
	var best string
	var bestN int64
	for _, v := range resp.Response.Versions {
		if v.VersionId == nil {
			continue
		}
		var n int64
		if _, err := fmt.Sscanf(*v.VersionId, "%d", &n); err == nil && n > bestN {
			bestN = n
			best = *v.VersionId
		}
	}
	if best == "" {
		return "", fmt.Errorf("no usable version id")
	}
	return best, nil
}

// IsTkePodIdentity reports whether the pod has TKE OIDC env vars bound
// (TKE_REGION / TKE_PROVIDER_ID / TKE_WEB_IDENTITY_TOKEN_FILE / TKE_ROLE_ARN).
// TKE's admission controller sets all four when the ServiceAccount is
// annotated eks.tke.cloud.tencent.com/role-arn. SDK fails when any one is
// missing, so we mirror that gate here to keep the fallback decision local.
func IsTkePodIdentity() bool {
	return os.Getenv("TKE_REGION") != "" &&
		os.Getenv("TKE_PROVIDER_ID") != "" &&
		os.Getenv("TKE_WEB_IDENTITY_TOKEN_FILE") != "" &&
		os.Getenv("TKE_ROLE_ARN") != ""
}

// PodIdentityCredential returns a CredentialIface backed by TKE OIDC.
// Errors when env is incomplete (callers should pre-check IsTkePodIdentity).
func PodIdentityCredential() (tccommon.CredentialIface, error) {
	provider, err := tccommon.DefaultTkeOIDCRoleArnProvider()
	if err != nil {
		return nil, err
	}
	return provider.GetCredential()
}

// StaticCredential wraps a known AK/SK pair as a CredentialIface. Use when
// running off TKE (dev, EKS, on-prem) or as fallback when pod identity isn't
// available.
func StaticCredential(secretID, secretKey string) tccommon.CredentialIface {
	return tccommon.NewCredential(secretID, secretKey)
}

// ResolveCredential picks the credential source for a given reconcile.
// TKE OIDC wins when its env is present (the pod already has a CAM role
// bound — use it). Otherwise static AK/SK from spec.secretRef. Errors
// when neither path yields a usable credential.
func ResolveCredential(ctx context.Context, kube client.Client, secretRefName, secretRefNS string) (tccommon.CredentialIface, error) {
	if IsTkePodIdentity() {
		cred, err := PodIdentityCredential()
		if err != nil {
			return nil, fmt.Errorf("tencent: TKE OIDC: %w", err)
		}
		return cred, nil
	}
	if secretRefName == "" {
		return nil, fmt.Errorf("tencent: no TKE pod identity env and spec.secretRef.name is empty")
	}
	id, key, err := LoadStaticCredentials(ctx, kube, secretRefName, secretRefNS)
	if err != nil {
		return nil, err
	}
	return StaticCredential(id, key), nil
}

// LoadStaticCredentials resolves a Tencent SecretRef to (secretID, secretKey).
// Keys match TENCENTCLOUD_SECRET_ID/KEY env var convention. Returns an error
// when the k8s Secret is missing or empty.
func LoadStaticCredentials(ctx context.Context, c client.Client, name, namespace string) (string, string, error) {
	if name == "" {
		return "", "", fmt.Errorf("tencent: secret ref name is empty")
	}
	if namespace == "" {
		return "", "", fmt.Errorf("tencent: secret ref namespace is empty (set spec.secretRef.namespace explicitly)")
	}
	var s corev1.Secret
	if err := c.Get(ctx, types.NamespacedName{Name: name, Namespace: namespace}, &s); err != nil {
		return "", "", fmt.Errorf("tencent: get secret %s/%s: %w", namespace, name, err)
	}
	id := string(s.Data["secret-id"])
	key := string(s.Data["secret-key"])
	if id == "" || key == "" {
		return "", "", fmt.Errorf("tencent: secret %s/%s missing secret-id or secret-key", namespace, name)
	}
	return id, key, nil
}
