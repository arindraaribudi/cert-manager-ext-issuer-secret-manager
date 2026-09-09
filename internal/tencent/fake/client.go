// Package fake provides an in-memory Client for Tencent SSL tests.
// ponytail: keyed by SSL certificate ID.
package fake

import (
	"context"
	"fmt"
	"sync"
)

type Client struct {
	mu   sync.RWMutex
	data map[string][]byte
}

func New() *Client {
	return &Client{data: map[string][]byte{}}
}

func (c *Client) Set(certID string, payload []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.data[certID] = payload
}

func (c *Client) Fetch(ctx context.Context, certID string) ([]byte, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	p, ok := c.data[certID]
	if !ok {
		return nil, fmt.Errorf("tencent: cert %q not found", certID)
	}
	return p, nil
}
