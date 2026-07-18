package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
)

// EncryptionSetup is the pending state of an encryption-at-rest
// ceremony (initial setup or recovery-code rotation) between the call
// that issues recovery codes and the challenge that proves the user
// copied one. The prepared slots it holds are already wrapped - no
// secret material is stored - but nothing becomes a MailKeySlot until
// the challenge passes. Database-held (WebAuthnChallenge precedent)
// so any replica can complete a ceremony another began. Rows expire
// in minutes and are purged lazily; one row per user at a time.
type EncryptionSetup struct {
	ent.Schema
}

func (EncryptionSetup) Fields() []ent.Field {
	return []ent.Field{
		field.Enum("mode").
			Values("setup", "rotation"),
		// JSON array of prepared slots (type, label, version, and
		// base64 wrapped_key/nonce/kdf_salt).
		field.String("prepared").
			NotEmpty().
			Sensitive(),
		field.Int("attempts").
			Default(0),
		field.Time("expires_at"),
	}
}

func (EncryptionSetup) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("user", User.Type).
			Ref("encryption_setups").
			Unique().
			Required(),
	}
}
