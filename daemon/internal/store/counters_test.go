package store

import (
	"context"
	"sync"
	"testing"
)

func TestCounterValueNeverIncrementedReadsZero(t *testing.T) {
	client := leaseTestClient(t)
	got, err := CounterValue(context.Background(), client, "never_touched")
	if err != nil || got != 0 {
		t.Fatalf("got=%d err=%v, want 0,nil", got, err)
	}
}

func TestIncrementCounterAccumulates(t *testing.T) {
	client := leaseTestClient(t)
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		if err := IncrementCounter(ctx, client, CounterAuthFailures); err != nil {
			t.Fatal(err)
		}
	}
	got, err := CounterValue(ctx, client, CounterAuthFailures)
	if err != nil || got != 3 {
		t.Fatalf("got=%d err=%v, want 3,nil", got, err)
	}
}

// TestIncrementCounterConcurrent proves the upsert is actually atomic
// across concurrent callers, which is the entire reason the increment
// happens in the database rather than read-modify-write in Go: a race
// here would silently undercount failed logins and weaken the
// fail2ban/lockout heuristic with no test failing to flag it.
func TestIncrementCounterConcurrent(t *testing.T) {
	client := leaseTestClient(t)
	ctx := context.Background()
	const n = 50

	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- IncrementCounter(ctx, client, CounterAuthFailures)
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}

	got, err := CounterValue(ctx, client, CounterAuthFailures)
	if err != nil || got != n {
		t.Fatalf("got=%d err=%v, want %d,nil (a lost increment means a race)", got, err, n)
	}
}
