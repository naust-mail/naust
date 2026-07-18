package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

// CheckResult is the latest outcome of one status check, or of one
// domain instance of a per-domain check (domain empty otherwise). One
// row per (check, domain): the engine upserts on completion, so the
// panel always reads a full snapshot instantly instead of waiting for
// a run. Steps hold the structured diagnosis (expected vs observed
// per step) as JSON in the shape of checks.Step.
type CheckResult struct {
	ent.Schema
}

func (CheckResult) Fields() []ent.Field {
	return []ent.Field{
		field.String("check").
			NotEmpty(),
		field.String("domain").
			Default(""),
		field.String("category").
			NotEmpty(),
		// ok | warning | error | skipped
		field.String("status").
			NotEmpty(),
		field.String("message").
			Default(""),
		// JSON-encoded []checks.Step; opaque to the store.
		field.String("steps").
			Default("[]"),
		field.Time("ran_at"),
		field.Int64("elapsed_ms").
			Default(0),
		// Set when the result enters warning/error and preserved
		// across consecutive failures ("failing since ..."); cleared
		// when the check recovers.
		field.Time("first_failed_at").
			Optional().
			Nillable(),
	}
}

func (CheckResult) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("check", "domain").
			Unique(),
	}
}

// MetricSample is one observation of a scalar box metric (queue
// depth, free disk bytes, failed logins per hour), written by checks
// at their own cadence and pruned by age. Consumed by the deviation
// heuristics, which compare current values against rolling windows of
// this box's own history instead of hardcoded thresholds.
type MetricSample struct {
	ent.Schema
}

func (MetricSample) Fields() []ent.Field {
	return []ent.Field{
		field.String("metric").
			NotEmpty(),
		field.Time("sampled_at"),
		field.Float("value"),
	}
}

func (MetricSample) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("metric", "sampled_at"),
	}
}
