// Package controller — ClientCache is a small keyed cache for
// expensive-to-construct SDK clients (region/endpoint/credential-scoped).
// Shared by awscertctrl and tencentcertctrl so both avoid rebuilding an
// ACM/Tencent-SSL client on every Reconcile call.
package controller

import "sync"

// ClientCache caches values by key, building each value at most once per
// key. Safe for concurrent use. A build error is never cached — the next
// call for the same key retries.
//
// ponytail: unbounded map, no eviction/TTL. Bounded in practice by the
// number of distinct (region, endpoint, credential) combinations an
// operator configures across Issuers — small. Add eviction if that stops
// being true.
type ClientCache[K comparable, V any] struct {
	mu    sync.Mutex
	items map[K]V
}

// NewClientCache returns an empty cache.
func NewClientCache[K comparable, V any]() *ClientCache[K, V] {
	return &ClientCache[K, V]{items: make(map[K]V)}
}

// GetOrCreate returns the cached value for key, or calls build and caches
// the result on a cache miss. The cache's single mutex is held for the
// full call, including the build() call itself — a slow build blocks every
// other caller (any key), not just callers for the same key. Acceptable
// here: misses are rare (one per distinct region/endpoint/credential
// combo, ever) and build() calls are just SDK client construction, not a
// hot path.
func (c *ClientCache[K, V]) GetOrCreate(key K, build func() (V, error)) (V, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if v, ok := c.items[key]; ok {
		return v, nil
	}
	v, err := build()
	if err != nil {
		var zero V
		return zero, err
	}
	c.items[key] = v
	return v, nil
}
