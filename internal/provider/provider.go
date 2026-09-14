// Package provider defines the tiny interface every cloud SDK wrapper
// implements, plus the parsed Certificate struct the controllers consume.
// ponytail: keeps AWS/GCP/Tencent symmetric — each adapter does its own
// payload parsing so the reconciler never branches on provider.
package provider

import "context"

// Certificate is what the controller writes to the k8s Secret.
// Chain may be empty (no chain in source).
type Certificate struct {
	Certificate []byte
	PrivateKey  []byte
	Chain       []byte
}

// Provider fetches one secret-manager entry and returns parsed PEM fields.
// ref is the provider-specific identifier (SM name, GCP resource name, Tencent cert ID).
type Provider interface {
	Fetch(ctx context.Context, ref string) (*Certificate, error)
}
