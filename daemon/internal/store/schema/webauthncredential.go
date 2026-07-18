package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
)

// WebAuthnCredential is one registered passkey. The full credential
// record (public key, sign count, flags, transports) lives in data as
// the webauthn library's own JSON encoding - the library validates
// against every field it wrote, so picking it apart into columns would
// only invite drift. credential_id is duplicated out for the unique
// index and login lookup.
type WebAuthnCredential struct {
	ent.Schema
}

func (WebAuthnCredential) Fields() []ent.Field {
	return []ent.Field{
		field.Bytes("credential_id").
			Unique().
			NotEmpty(),
		// JSON of webauthn.Credential.
		field.String("data").
			NotEmpty().
			Sensitive(),
		field.String("name").
			Optional(),
		field.Time("created_at").
			Default(time.Now).
			Immutable(),
		field.Time("last_used").
			Optional().
			Nillable(),
	}
}

func (WebAuthnCredential) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("user", User.Type).
			Ref("webauthn_credentials").
			Unique().
			Required(),
	}
}
