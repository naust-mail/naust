package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
)

// WebAuthnChallenge is the server-side state of one in-flight WebAuthn
// ceremony (register or login), keyed by a single-use nonce handed to
// the client between the begin and complete calls. Stored in the
// database - not process memory - so any replica can complete a
// ceremony another replica began. Rows expire in minutes and are
// purged lazily.
type WebAuthnChallenge struct {
	ent.Schema
}

func (WebAuthnChallenge) Fields() []ent.Field {
	return []ent.Field{
		// SHA-256 of the nonce; the plaintext nonce exists only at the
		// client, like session tokens.
		field.String("nonce_hash").
			Unique().
			Sensitive(),
		// JSON of webauthn.SessionData.
		field.String("session_data").
			NotEmpty().
			Sensitive(),
		// prf ceremonies are assertion-shaped like login but must never
		// be redeemable as one (a prf nonce cannot mint a session), so
		// they are a distinct kind.
		field.Enum("kind").
			Values("register", "login", "prf"),
		field.Time("expires_at"),
	}
}

func (WebAuthnChallenge) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("user", User.Type).
			Ref("webauthn_challenges").
			Unique().
			Required(),
	}
}
