package controller

import (
	"errors"
	"sync"
	"testing"
)

func TestClientCache_GetOrCreate_CachesOnKey(t *testing.T) {
	c := NewClientCache[string, int]()
	calls := 0
	build := func() (int, error) { calls++; return 42, nil }

	v1, err := c.GetOrCreate("a", build)
	if err != nil || v1 != 42 {
		t.Fatalf("first call: v=%d err=%v", v1, err)
	}
	v2, err := c.GetOrCreate("a", build)
	if err != nil || v2 != 42 {
		t.Fatalf("second call: v=%d err=%v", v2, err)
	}
	if calls != 1 {
		t.Fatalf("build called %d times, want 1 (cache hit expected)", calls)
	}

	_, err = c.GetOrCreate("b", build)
	if err != nil {
		t.Fatalf("different key: err=%v", err)
	}
	if calls != 2 {
		t.Fatalf("build called %d times, want 2 (new key = new build)", calls)
	}
}

func TestClientCache_GetOrCreate_BuildErrorNotCached(t *testing.T) {
	c := NewClientCache[string, int]()
	calls := 0
	failFirst := func() (int, error) {
		calls++
		if calls == 1 {
			return 0, errors.New("boom")
		}
		return 7, nil
	}
	if _, err := c.GetOrCreate("k", failFirst); err == nil {
		t.Fatal("want error on first call")
	}
	v, err := c.GetOrCreate("k", failFirst)
	if err != nil || v != 7 {
		t.Fatalf("retry after error: v=%d err=%v, want 7/nil", v, err)
	}
	if calls != 2 {
		t.Fatalf("build called %d times, want 2 (error must not be cached)", calls)
	}
}

func TestClientCache_GetOrCreate_ConcurrentSameKey(t *testing.T) {
	c := NewClientCache[string, int]()
	var calls int
	var mu sync.Mutex
	build := func() (int, error) {
		mu.Lock()
		calls++
		mu.Unlock()
		return 1, nil
	}
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := c.GetOrCreate("k", build); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if calls != 1 {
		t.Fatalf("build called %d times under concurrency, want 1", calls)
	}
}
