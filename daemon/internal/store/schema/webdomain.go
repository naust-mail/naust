package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
)

// WebDomain holds an operator's web customizations for one hosted
// domain: the per-domain scalars here, the path rules as WebRule rows.
// Replaces the legacy www/custom.yaml file. A domain with no row is
// served entirely with defaults, so this table only grows when someone
// customizes. Saving a domain's settings replaces its whole rule set in
// one transaction; rules have no identity worth preserving across edits.
type WebDomain struct {
	ent.Schema
}

func (WebDomain) Fields() []ent.Field {
	return []ent.Field{
		// Fully qualified, lowercase, punycoded at the API boundary.
		field.String("domain").
			Unique().
			NotEmpty(),
		// Strict-Transport-Security level: "on" is the plain header,
		// "preload" adds includeSubDomains+preload, "off" omits it.
		field.Enum("hsts").
			Values("on", "preload", "off").
			Default("on"),
		// When false the domain gets no static file serving, only its
		// system paths (ACME, autoconfig) and any rules below.
		field.Bool("serve_static").
			Default(true),
		field.Time("created_at").
			Default(time.Now).
			Immutable(),
	}
}

func (WebDomain) Edges() []ent.Edge {
	return []ent.Edge{
		edge.To("rules", WebRule.Type),
		edge.From("tenant", Tenant.Type).
			Ref("web_domains").
			Unique().
			Required(),
	}
}
