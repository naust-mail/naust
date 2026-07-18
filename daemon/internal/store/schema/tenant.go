package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
)

// Tenant is one isolated customer organization on this deployment.
// Single-box installs hold exactly one row, named "default", created
// at schema setup - every tenant-owned row is born with its owner so
// multi-tenancy (the MSP/hoster deployment model) is a v2 feature,
// not a data migration. Only the aggregates a tenant owns carry the
// edge; user satellites (sessions, tokens, credentials, key slots)
// derive tenancy through their user, and box infrastructure
// (settings, backups, checks, leases) is the operator's, never a
// tenant's.
//
// HARD GATE for v2: query scoping (the automatic per-tenant filter)
// must exist before any way to create a second tenant does.
type Tenant struct {
	ent.Schema
}

func (Tenant) Fields() []ent.Field {
	return []ent.Field{
		field.String("name").
			Unique().
			NotEmpty(),
		field.Time("created_at").
			Default(time.Now).
			Immutable(),
	}
}

func (Tenant) Edges() []ent.Edge {
	// No cascade: deleting a tenant that still owns rows must fail;
	// offboarding is an explicit v2 flow, not a foreign-key side
	// effect.
	return []ent.Edge{
		edge.To("users", User.Type),
		edge.To("aliases", Alias.Type),
		edge.To("web_domains", WebDomain.Type),
		edge.To("dns_records", DNSRecord.Type),
		edge.To("dns_zone_providers", DNSZoneProvider.Type),
	}
}
