package acmeprov

import (
	"context"
	"errors"
	"sync"
	"testing"
)

// memProvider is an in-memory dnsprovider.Provider: the DNS-01 tests
// exercise the solver and selector; the real API clients have their
// own request-shape tests in internal/dnsprovider.
type memProvider struct {
	mu      sync.Mutex
	records map[string]string // fqdn -> value
	created []string
	zone    string
}

func (m *memProvider) SetTXT(_ context.Context, zone, fqdn, value string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.records == nil {
		m.records = map[string]string{}
	}
	m.zone = zone
	m.records[fqdn] = value
	m.created = append(m.created, fqdn)
	return nil
}

func (m *memProvider) DeleteTXT(_ context.Context, zone, fqdn, value string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.records[fqdn] == value {
		delete(m.records, fqdn)
	}
	return nil
}

func (m *memProvider) has(fqdn string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.records[fqdn]
	return ok
}

func (m *memProvider) count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.records)
}

func TestWaitForTXT(t *testing.T) {
	ctx := context.Background()
	// Found on the first poll: returns immediately.
	err := waitForTXT(ctx, "z", "f", "v", func(context.Context, string, string) ([]string, error) {
		return []string{"other", "v"}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// Never found: a cancelled context ends the wait with an error.
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	err = waitForTXT(cancelled, "z", "f", "v", func(context.Context, string, string) ([]string, error) {
		return nil, errors.New("nxdomain")
	})
	if err == nil {
		t.Fatal("expected error from cancelled wait")
	}
}
