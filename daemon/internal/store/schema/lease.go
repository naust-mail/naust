package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/field"
)

// Lease is a singleton claim on a named background job (backup run,
// status-check batch, ACME renewal pass). Replicas acquire the row
// with a compare-and-swap update before running, so exactly one
// process does the work no matter how many serve requests
// (stateless-process rule: coordination lives in the store, never in
// process memory).
type Lease struct {
	ent.Schema
}

func (Lease) Fields() []ent.Field {
	return []ent.Field{
		field.String("name").
			Unique().
			NotEmpty(),
		// Holder identifies the owning process (host:pid); the same
		// holder may re-acquire its own live lease.
		field.String("holder"),
		field.Time("expires_at"),
	}
}
