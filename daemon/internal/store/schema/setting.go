package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/field"
)

// Setting is a singleton configuration value keyed by name, with the
// value JSON-encoded. Replaces the legacy settings.yaml plus the fake
// "_secondary_nameserver" record that hid inside custom.yaml. Known
// keys are constants in the packages that own them.
type Setting struct {
	ent.Schema
}

func (Setting) Fields() []ent.Field {
	return []ent.Field{
		field.String("key").
			Unique().
			NotEmpty(),
		field.String("value"),
	}
}
