package store

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"naust/daemon/internal/store/ent"
	entlease "naust/daemon/internal/store/ent/lease"
)

func leaseTestClient(t *testing.T) *ent.Client {
	t.Helper()
	client, err := Open(EngineSQLite, filepath.Join(t.TempDir(), "test.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() })
	if err := client.Schema.Create(context.Background()); err != nil {
		t.Fatal(err)
	}
	return client
}

func TestLeaseAcquireAndReacquire(t *testing.T) {
	ctx := context.Background()
	client := leaseTestClient(t)

	got, err := AcquireLease(ctx, client, "backup", time.Hour)
	if err != nil || !got {
		t.Fatalf("first acquire = %v, %v", got, err)
	}
	// The same process may re-acquire its own live lease.
	got, err = AcquireLease(ctx, client, "backup", time.Hour)
	if err != nil || !got {
		t.Fatalf("re-acquire = %v, %v", got, err)
	}
}

func TestLeaseHeldByAnotherProcess(t *testing.T) {
	ctx := context.Background()
	client := leaseTestClient(t)

	if _, err := AcquireLease(ctx, client, "backup", time.Hour); err != nil {
		t.Fatal(err)
	}
	// Simulate another process's live claim.
	if _, err := client.Lease.Update().
		Where(entlease.Name("backup")).
		SetHolder("otherhost:1").
		Save(ctx); err != nil {
		t.Fatal(err)
	}

	got, err := AcquireLease(ctx, client, "backup", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if got {
		t.Fatal("acquired a lease another live process holds")
	}

	// Release by a non-holder must not free it.
	if err := ReleaseLease(ctx, client, "backup"); err != nil {
		t.Fatal(err)
	}
	if got, _ := AcquireLease(ctx, client, "backup", time.Hour); got {
		t.Fatal("non-holder release freed the lease")
	}
}

func TestLeaseExpiryAndRelease(t *testing.T) {
	ctx := context.Background()
	client := leaseTestClient(t)

	// A crashed holder: claim exists but has lapsed.
	if _, err := client.Lease.Create().
		SetName("backup").
		SetHolder("otherhost:1").
		SetExpiresAt(time.Now().Add(-time.Minute)).
		Save(ctx); err != nil {
		t.Fatal(err)
	}
	got, err := AcquireLease(ctx, client, "backup", time.Hour)
	if err != nil || !got {
		t.Fatalf("acquire over expired claim = %v, %v", got, err)
	}

	// Release, then a fresh holder can take it immediately.
	if err := ReleaseLease(ctx, client, "backup"); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Lease.Update().
		Where(entlease.Name("backup")).
		SetHolder("otherhost:1").
		Save(ctx); err != nil {
		t.Fatal(err)
	}
	// The other holder's expires_at is the released (past) one, so
	// the claim is takeable.
	if got, _ := AcquireLease(ctx, client, "backup", time.Hour); !got {
		t.Fatal("released lease was not takeable")
	}
}

func TestCounterIncrementAndRead(t *testing.T) {
	ctx := context.Background()
	client := leaseTestClient(t)

	if v, err := CounterValue(ctx, client, CounterAuthFailures); err != nil || v != 0 {
		t.Fatalf("missing counter = %d, %v", v, err)
	}
	for i := 0; i < 3; i++ {
		if err := IncrementCounter(ctx, client, CounterAuthFailures); err != nil {
			t.Fatal(err)
		}
	}
	if v, err := CounterValue(ctx, client, CounterAuthFailures); err != nil || v != 3 {
		t.Fatalf("counter = %d, %v", v, err)
	}
}
