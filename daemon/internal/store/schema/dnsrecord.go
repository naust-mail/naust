package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

// DNSRecord is a custom DNS record set by the operator, layered on top
// of the records the box generates for its own domains. Replaces the
// legacy dns/custom.yaml file. The legacy fake "_secondary_nameserver"
// entry does not live here: secondary nameservers are a Setting.
type DNSRecord struct {
	ent.Schema
}

func (DNSRecord) Fields() []ent.Field {
	return []ent.Field{
		// Fully qualified name, lowercase, no trailing dot.
		field.String("qname").
			NotEmpty(),
		field.Enum("rtype").
			Values("A", "AAAA", "CNAME", "NS", "TXT", "SRV", "MX", "SSHFP", "CAA"),
		// For A/AAAA the literal "local" means this box's public IP,
		// resolved when zones are generated.
		field.String("value").
			NotEmpty(),
		field.Time("created_at").
			Default(time.Now).
			Immutable(),
	}
}

func (DNSRecord) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("tenant", Tenant.Type).
			Ref("dns_records").
			Unique().
			Required(),
	}
}

func (DNSRecord) Indexes() []ent.Index {
	return []ent.Index{
		// A qname+rtype pair may hold several values (round-robin A,
		// multiple TXT), but exact duplicates are meaningless.
		index.Fields("qname", "rtype", "value").
			Unique(),
	}
}
