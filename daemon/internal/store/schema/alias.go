package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
)

// Alias is a mail forwarding rule. Replaces both the legacy aliases and
// auto_aliases tables: system-generated rows (postmaster@, abuse@, ...)
// carry auto=true instead of living in a parallel table.
type Alias struct {
	ent.Schema
}

func (Alias) Fields() []ent.Field {
	return []ent.Field{
		field.String("source").
			Unique().
			NotEmpty(),
		// Forward-to addresses. Typed list instead of the legacy
		// comma-separated text column.
		field.Strings("destinations"),
		// Addresses allowed to send as this alias. Empty means the
		// alias's own destinations may send as it (legacy semantics).
		field.Strings("permitted_senders").
			Optional(),
		field.Bool("auto").
			Default(false),
		field.Time("created_at").
			Default(time.Now).
			Immutable(),
	}
}

func (Alias) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("tenant", Tenant.Type).
			Ref("aliases").
			Unique().
			Required(),
	}
}
