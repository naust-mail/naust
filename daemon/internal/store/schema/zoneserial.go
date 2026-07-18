package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/field"
)

// ZoneSerial tracks, per hosted DNS zone, the last serial number
// published and a hash of the zone content it covered. The zone file
// on disk is pure output: change detection compares the hash here, and
// the next serial derives from the one here, so the daemon never reads
// its own generated files to recover state.
type ZoneSerial struct {
	ent.Schema
}

func (ZoneSerial) Fields() []ent.Field {
	return []ent.Field{
		field.String("zone").
			Unique().
			NotEmpty(),
		// Date-based convention YYYYMMDDNN, stored as a number so
		// bumping is arithmetic, not string surgery.
		field.Int64("serial").
			Positive(),
		// SHA-256 of the rendered zone with the serial zeroed; equal
		// hash means nothing but the serial would change.
		field.String("content_hash").
			NotEmpty(),
	}
}
