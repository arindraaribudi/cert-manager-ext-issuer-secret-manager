// Package gcp wraps the GCP Secret Manager client behind a Fetch interface.
// ponytail: SDK call only; JSON parsing happens in internal/controller/parse.go.
package gcp

import (
	"context"
	"fmt"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	"google.golang.org/api/option"
)

// New builds a Secret Manager client. If adcJSON is non-empty it's used as
// ADC credentials (else Workload Identity / ADC chain).
func New(ctx context.Context, adcJSON []byte) (*secretmanager.Client, error) {
	var opts []option.ClientOption
	if len(adcJSON) > 0 {
		opts = append(opts, option.WithCredentialsJSON(adcJSON)) //nolint:staticcheck // SA1019: ADC JSON path; replace when SDK ships non-deprecated constructor
	}
	cli, err := secretmanager.NewClient(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("gcp: new client: %w", err)
	}
	return cli, nil
}

// Fetch returns the latest payload as raw bytes. ref is the full GCP resource
// name (projects/.../secrets/.../versions/...).
func Fetch(ctx context.Context, api *secretmanager.Client, ref string) ([]byte, error) {
	req := &secretmanagerpb.AccessSecretVersionRequest{Name: ref}
	out, err := api.AccessSecretVersion(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("gcp: access %q: %w", ref, err)
	}
	return out.Payload.Data, nil
}
