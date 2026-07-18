package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/field"
)

// Counter is a named monotonic counter incremented atomically in the
// database, so totals are shared across replicas and survive restarts
// (the login-failure heuristic samples these; an in-process counter
// would undercount behind a load balancer and reset on every deploy).
type Counter struct {
	ent.Schema
}

func (Counter) Fields() []ent.Field {
	return []ent.Field{
		field.String("name").
			Unique().
			NotEmpty(),
		field.Int64("value").
			Default(0),
	}
}
