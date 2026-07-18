package store

import (
	"context"

	"naust/daemon/internal/store/ent"
	enttenant "naust/daemon/internal/store/ent/tenant"
)

// DefaultTenantName names the tenant every single-box install lives
// in. The row's ID is looked up, never assumed: no hardcoded-ID
// contract.
const DefaultTenantName = "default"

// EnsureDefaultTenant creates the default tenant if missing and
// returns it. Runs at startup right after schema migration, so
// tenant-owned rows always have an owner to be born under.
func EnsureDefaultTenant(ctx context.Context, c *ent.Client) (*ent.Tenant, error) {
	err := c.Tenant.Create().
		SetName(DefaultTenantName).
		OnConflictColumns(enttenant.FieldName).
		Ignore().
		Exec(ctx)
	if err != nil {
		return nil, err
	}
	return c.Tenant.Query().
		Where(enttenant.Name(DefaultTenantName)).
		Only(ctx)
}
