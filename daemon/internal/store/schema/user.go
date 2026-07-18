// Package schema defines the control-plane data model as ent schemas.
//
// This is the source of truth for the manager's database across every
// supported engine (SQLite default, Postgres opt-in). Nothing above the
// store layer may know which engine is in use, so schema definitions here
// must stay portable: no dialect-specific column types, no raw SQL
// defaults.
//
// Deliberate departures from the legacy Python users.sqlite schema
// (permitted while nothing is deployed - the "constraints window"):
//   - users.extra dropped: never read or written by any code path
//   - users.privileges (newline-separated text, only ever "admin")
//     collapsed to a typed role enum; new roles are code additions
//   - users.quota (TEXT holding a number) becomes quota_bytes int64
//   - users.home_node added now so multi-mail-node routing is a feature,
//     not a migration
package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
)

// User is a mail account. Also the anchor for every credential type.
type User struct {
	ent.Schema
}

func (User) Fields() []ent.Field {
	return []ent.Field{
		field.String("email").
			Unique().
			NotEmpty(),
		field.String("password_hash").
			Sensitive(),
		// Coarse authorization anchor. Finer-grained gating (per-intent
		// permissions, more roles) keys off this later without a schema
		// shape change: ent enums are strings validated in code.
		field.Enum("role").
			Values("admin", "user").
			Default("user"),
		// 0 means unlimited.
		field.Int64("quota_bytes").
			NonNegative().
			Default(0),
		// Which mail node hosts this user's mailbox. Empty string means
		// the single local node; only multi-node deployments set it.
		field.String("home_node").
			Default(""),
		field.Time("created_at").
			Default(time.Now).
			Immutable(),
	}
}

func (User) Edges() []ent.Edge {
	return []ent.Edge{
		edge.To("sessions", Session.Type).
			Annotations(entsql.OnDelete(entsql.Cascade)),
		edge.To("api_tokens", APIToken.Type).
			Annotations(entsql.OnDelete(entsql.Cascade)),
		edge.To("totp_credentials", TOTPCredential.Type).
			Annotations(entsql.OnDelete(entsql.Cascade)),
		edge.To("webauthn_credentials", WebAuthnCredential.Type).
			Annotations(entsql.OnDelete(entsql.Cascade)),
		edge.To("webauthn_challenges", WebAuthnChallenge.Type).
			Annotations(entsql.OnDelete(entsql.Cascade)),
		edge.To("mail_key_slots", MailKeySlot.Type).
			Annotations(entsql.OnDelete(entsql.Cascade)),
		edge.To("encryption_setups", EncryptionSetup.Type).
			Annotations(entsql.OnDelete(entsql.Cascade)),
		edge.From("tenant", Tenant.Type).
			Ref("users").
			Unique().
			Required(),
	}
}
