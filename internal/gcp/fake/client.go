// Package fake provides an in-memory Client for GCP Secret Manager tests.
// ponytail: keyed by full resource name (matches the cloud identifier).
package fake

import (
	"context"
	"fmt"
	"sync"
)

type Client struct {
	mu       sync.RWMutex
	payloads map[string][]byte
}

func New() *Client {
	return &Client{payloads: map[string][]byte{}}
}

func (c *Client) Set(resourceName string, payload []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.payloads[resourceName] = payload
}

func (c *Client) Fetch(ctx context.Context, resourceName string) ([]byte, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	p, ok := c.payloads[resourceName]
	if !ok {
		return nil, fmt.Errorf("gcp: secret %q not found", resourceName)
	}
	return p, nil
}
