// Package store owns every database concern: schema, generated ent
// client, engine selection, and connection setup. Nothing outside this
// package knows which engine is in use.
package store

//go:generate go run -mod=mod entgo.io/ent/cmd/ent generate --feature sql/upsert --target ./ent ./schema
