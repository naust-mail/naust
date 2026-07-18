package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

// AuthFailure is one failed credential attempt against a windowed
// endpoint, kept for per-email sliding-window rate limits. kind names
// the window ("relink" for recovery-code relinks, "verify" for the
// internal mail-user verify endpoint) so one endpoint's failures never
// count against another's limit. Rows inside the window are counted
// per email; success clears them and old rows are pruned
// opportunistically. Stored in the database so the limit holds across
// restarts and replicas.
type AuthFailure struct {
	ent.Schema
}

func (AuthFailure) Fields() []ent.Field {
	return []ent.Field{
		field.String("kind").
			NotEmpty(),
		field.String("email").
			NotEmpty(),
		field.Time("at").
			Default(time.Now).
			Immutable(),
	}
}

func (AuthFailure) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("kind", "email"),
	}
}
