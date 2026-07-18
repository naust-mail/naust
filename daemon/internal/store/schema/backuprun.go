package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

// BackupRun is one execution of the nightly (or manual) backup. The
// engine inserts a running row at start and completes it at the end,
// so an abandoned "running" row after a crash is visible history, not
// hidden state. Old rows are pruned; the panel reads the recent list.
type BackupRun struct {
	ent.Schema
}

func (BackupRun) Fields() []ent.Field {
	return []ent.Field{
		field.Time("started_at"),
		field.Time("finished_at").
			Optional().
			Nillable(),
		// running | ok | error
		field.String("status").
			NotEmpty(),
		// restic | duplicity
		field.String("tool").
			NotEmpty(),
		// Error holds the failure detail; Warning holds non-fatal
		// problems of a successful run (retention prune failed) that
		// the backup check must surface without failing the backup.
		field.String("error").
			Default(""),
		field.String("warning").
			Default(""),
		// JSON stats from the tool (snapshot id, bytes, file count);
		// opaque to the store.
		field.String("stats").
			Default("{}"),
	}
}

func (BackupRun) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("started_at"),
	}
}
