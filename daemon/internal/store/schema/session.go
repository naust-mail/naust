package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
)

// Session is a browser login session. Sessions live in the database, not
// process memory, so any manager replica can serve any request and the
// process is disposable at all times (stateless-process rule).
type Session struct {
	ent.Schema
}

func (Session) Fields() []ent.Field {
	return []ent.Field{
		// SHA-256 of the bearer token; the token itself is never stored.
		field.String("token_hash").
			Unique().
			NotEmpty().
			Sensitive(),
		field.Time("created_at").
			Default(time.Now).
			Immutable(),
		field.Time("expires_at"),
		field.Time("last_used").
			Optional().
			Nillable(),
	}
}

func (Session) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("user", User.Type).
			Ref("sessions").
			Unique().
			Required(),
	}
}
