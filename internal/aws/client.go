// Package aws wraps the AWS Secrets Manager SDK behind a Fetch interface.
// ponytail: SDK call only; JSON parsing happens in internal/controller/parse.go.
package aws

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
)

type Client struct {
	api *secretsmanager.Client
}

// New builds a Secrets Manager client for the given region.
// Credentials come from the default SDK chain (env / shared config / IRSA).
func New(ctx context.Context, region string) (*Client, error) {
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("aws: load config: %w", err)
	}
	return &Client{api: secretsmanager.NewFromConfig(cfg)}, nil
}

// Fetch returns the SecretString payload as raw bytes.
func (c *Client) Fetch(ctx context.Context, name string) ([]byte, error) {
	out, err := c.api.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{SecretId: &name})
	if err != nil {
		return nil, fmt.Errorf("aws: get secret %q: %w", name, err)
	}
	if out.SecretString == nil {
		return nil, fmt.Errorf("aws: secret %q has no SecretString", name)
	}
	return []byte(*out.SecretString), nil
}
