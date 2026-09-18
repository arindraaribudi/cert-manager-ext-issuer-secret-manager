// Package awscert credentials: SDK chain (IRSA via web identity / STS /
// EC2 metadata) by default; static Secret fallback when spec.SecretRef is set.
// ponytail: aws-sdk-go-v2/config already implements the chain — we just
// compose. No custom token refresh.
package awscert

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	certapi "github.com/arindraaribudi/cert-manager-ext-issuer-secret-manager/api/certificates/v1alpha1"
)

// BuildCredentialConfig returns an aws.Config using the SDK's default chain.
// Honors IRSA via STS web identity, then env vars, then EC2 instance role.
func BuildCredentialConfig(ctx context.Context, region string) (aws.Config, error) {
	return awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(region))
}

// LoadStaticCredentials reads access-key-id + secret-access-key from a
// k8s Secret and builds an aws.Config using a static credentials provider.
// session-token is optional. Passphrase is NOT read here; pass it separately.
func LoadStaticCredentials(ctx context.Context, c client.Client, name, namespace string) (aws.Config, error) {
	var s corev1.Secret
	if err := c.Get(ctx, client.ObjectKey{Name: name, Namespace: namespace}, &s); err != nil {
		return aws.Config{}, fmt.Errorf("awscert: get secret: %w", err)
	}
	id := string(s.Data["access-key-id"])
	key := string(s.Data["secret-access-key"])
	if id == "" || key == "" {
		return aws.Config{}, fmt.Errorf("awscert: secret %s/%s missing access-key-id or secret-access-key", namespace, name)
	}
	creds := aws.NewCredentialsCache(credentials.NewStaticCredentialsProvider(id, key, ""))
	cfg, err := awsconfig.LoadDefaultConfig(ctx,
		awsconfig.WithCredentialsProvider(creds),
	)
	if err != nil {
		return aws.Config{}, fmt.Errorf("awscert: load config: %w", err)
	}
	return cfg, nil
}

// LoadPassphrase reads the optional `passphrase` key from the same Secret
// referenced by SecretRef. Returns "" if absent — caller decides whether
// absence is fatal (private-key export requires it).
func LoadPassphrase(ctx context.Context, c client.Client, ref *certapi.AWSSecretRef, defaultNS string) (string, error) {
	if ref == nil {
		return "", nil
	}
	ns := ref.Namespace
	if ns == "" {
		ns = defaultNS
	}
	var s corev1.Secret
	if err := c.Get(ctx, client.ObjectKey{Name: ref.Name, Namespace: ns}, &s); err != nil {
		return "", fmt.Errorf("awscert: get secret for passphrase: %w", err)
	}
	return string(s.Data["passphrase"]), nil
}
