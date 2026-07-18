package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
)

// APIToken is a long-lived automation credential (naust_<64hex> format).
type APIToken struct {
	ent.Schema
}

func (APIToken) Fields() []ent.Field {
	return []ent.Field{
		field.String("name").
			NotEmpty(),
		field.String("token_hash").
			Unique().
			NotEmpty().
			Sensitive(),
		field.Enum("scope").
			Values("read", "write").
			Default("read"),
		field.Time("created_at").
			Default(time.Now).
			Immutable(),
		field.Time("last_used").
			Optional().
			Nillable(),
	}
}

func (APIToken) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("user", User.Type).
			Ref("api_tokens").
			Unique().
			Required(),
	}
}
