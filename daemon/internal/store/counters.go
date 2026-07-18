package store

import (
	"context"

	"naust/daemon/internal/store/ent"
	entcounter "naust/daemon/internal/store/ent/counter"
)

// CounterAuthFailures totals failed logins and failed encryption
// ceremonies across all replicas; the login-failure status heuristic
// samples it hourly.
const CounterAuthFailures = "auth_failures_total"

// IncrementCounter adds one to the named counter, creating it at 1.
// The increment happens in the database, so it is atomic across
// replicas.
func IncrementCounter(ctx context.Context, c *ent.Client, name string) error {
	return c.Counter.Create().
		SetName(name).
		SetValue(1).
		OnConflictColumns(entcounter.FieldName).
		Update(func(u *ent.CounterUpsert) {
			u.AddValue(1)
		}).
		Exec(ctx)
}

// CounterValue reads the named counter; a counter that was never
// incremented reads 0.
func CounterValue(ctx context.Context, c *ent.Client, name string) (int64, error) {
	row, err := c.Counter.Query().
		Where(entcounter.Name(name)).
		Only(ctx)
	if ent.IsNotFound(err) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	return row.Value, nil
}
