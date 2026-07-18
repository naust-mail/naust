package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
)

// TOTPCredential is one enrolled authenticator app. Replaces the legacy
// mfa table; its type column is gone because TOTP was the only value.
type TOTPCredential struct {
	ent.Schema
}

func (TOTPCredential) Fields() []ent.Field {
	return []ent.Field{
		field.String("secret").
			NotEmpty().
			Sensitive(),
		// Most recently consumed 30-second time step (zero-padded so
		// string comparison orders numerically), kept to reject replay:
		// a code is accepted once, via a conditional update that only
		// moves this value forward.
		field.String("mru_token").
			Optional().
			Nillable().
			Sensitive(),
		field.String("label").
			Optional(),
		field.Time("created_at").
			Default(time.Now).
			Immutable(),
	}
}

func (TOTPCredential) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("user", User.Type).
			Ref("totp_credentials").
			Unique().
			Required(),
	}
}
