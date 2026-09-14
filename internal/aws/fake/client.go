// Package fake provides an in-memory Client for tests and demos.
// ponytail: keyed by secret name, no version support in v1.
package fake

import (
	"context"
	"fmt"
	"sync"
)

type Client struct {
	mu      sync.RWMutex
	secrets map[string][]byte
}

func New() *Client {
	return &Client{secrets: map[string][]byte{}}
}

func (c *Client) Set(name string, payload []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.secrets[name] = payload
}

// Fetch returns the raw JSON payload stored under name.
func (c *Client) Fetch(ctx context.Context, name string) ([]byte, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	p, ok := c.secrets[name]
	if !ok {
		return nil, fmt.Errorf("aws: secret %q not found", name)
	}
	return p, nil
}
