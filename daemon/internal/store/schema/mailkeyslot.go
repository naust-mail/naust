package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

// MailKeySlot is one wrapped copy of a user's mail encryption root
// key. Any single slot unwraps the same root key; slots are
// independent so losing one credential never loses mail. The wrap
// binds (user, slot_type, label, version) as AEAD associated data, so
// rows cannot be moved between users or slot types undetected. See
// internal/mailcrypt for the crypto.
type MailKeySlot struct {
	ent.Schema
}

func (MailKeySlot) Fields() []ent.Field {
	return []ent.Field{
		field.Enum("slot_type").
			Values("password", "recovery_code", "app_password", "passkey_prf"),
		// Distinguishes slots of the same type: recovery code index
		// ("0".."3"), passkey_prf = WebAuthn credential ID (base64).
		// Empty for the password slot.
		field.String("label").
			Default(""),
		// Crypto parameter version bound into the AAD; bumps allow
		// lazy re-wrap on the next successful unwrap.
		field.Int("version"),
		field.Bytes("wrapped_key").
			Sensitive(),
		field.Bytes("nonce").
			Sensitive(),
		field.Bytes("kdf_salt").
			Sensitive(),
		// WebAuthn PRF eval salt sent to the authenticator; set only
		// on passkey_prf slots.
		field.Bytes("prf_salt").
			Optional().
			Sensitive(),
		field.Time("created_at").
			Default(time.Now).
			Immutable(),
	}
}

func (MailKeySlot) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("user", User.Type).
			Ref("mail_key_slots").
			Unique().
			Required(),
	}
}

func (MailKeySlot) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("slot_type").
			Edges("user"),
	}
}
