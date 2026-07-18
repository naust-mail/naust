package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
)

// DNSZoneProvider records who hosts a zone's public DNS when it is
// not this box, so certificate provisioning can fulfill DNS-01
// challenges through the provider's API (Cloudflare, DigitalOcean,
// Hetzner). A zone with no row is hosted here (or on unmanaged
// external DNS): HTTP-01 with the points-here gate applies, exactly
// as before. Providers only ever add capability.
type DNSZoneProvider struct {
	ent.Schema
}

func (DNSZoneProvider) Fields() []ent.Field {
	return []ent.Field{
		// Fully qualified, lowercase, punycoded at the API boundary.
		field.String("zone").
			Unique().
			NotEmpty(),
		// Registry name of the provider plugin (acmeprov.Providers).
		field.String("provider").
			NotEmpty(),
		// API credential. Scoped as narrowly as the provider allows
		// (e.g. a Cloudflare token restricted to DNS edits on the
		// zone). Never returned by the API.
		field.String("token").
			NotEmpty().
			Sensitive(),
		field.Time("created_at").
			Default(time.Now).
			Immutable(),
	}
}

func (DNSZoneProvider) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("tenant", Tenant.Type).
			Ref("dns_zone_providers").
			Unique().
			Required(),
	}
}
