package store

import (
	"context"
	"fmt"
	"os"
	"time"

	"naust/daemon/internal/store/ent"
	entlease "naust/daemon/internal/store/ent/lease"
)

// processHolder identifies this process in lease rows. host:pid is
// unique across a fleet sharing one store; a process may re-acquire
// its own live lease (kick and timer paths overlap harmlessly).
var processHolder = func() string {
	host, err := os.Hostname()
	if err != nil {
		host = "unknown"
	}
	return fmt.Sprintf("%s:%d", host, os.Getpid())
}()

// AcquireLease claims the named singleton lease for this process for
// ttl. It reports false when another live process holds it. Callers
// release on completion; a crashed holder's claim lapses at
// expires_at, so ttl bounds how long work stays blocked after a
// crash.
func AcquireLease(ctx context.Context, c *ent.Client, name string, ttl time.Duration) (bool, error) {
	now := time.Now()
	// Materialize the row (already-claimable: empty holder, expired).
	err := c.Lease.Create().
		SetName(name).
		SetHolder("").
		SetExpiresAt(now).
		OnConflictColumns(entlease.FieldName).
		Ignore().
		Exec(ctx)
	if err != nil {
		return false, err
	}
	// The compare-and-swap: only an expired or own claim can be taken.
	n, err := c.Lease.Update().
		Where(
			entlease.Name(name),
			entlease.Or(
				entlease.ExpiresAtLTE(now),
				entlease.Holder(processHolder),
			),
		).
		SetHolder(processHolder).
		SetExpiresAt(now.Add(ttl)).
		Save(ctx)
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

// ReleaseLease lapses this process's claim on the named lease
// immediately. A no-op when another process holds it.
func ReleaseLease(ctx context.Context, c *ent.Client, name string) error {
	_, err := c.Lease.Update().
		Where(entlease.Name(name), entlease.Holder(processHolder)).
		SetExpiresAt(time.Now()).
		Save(ctx)
	return err
}
