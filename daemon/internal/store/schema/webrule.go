package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

// WebRule is one path rule on a WebDomain: a reverse proxy, a redirect,
// or a filesystem alias. A rule at path "/" is the domain's root
// override (the domain stops serving static files there). Every field
// is a real column so the set stays queryable: "what proxies to this
// backend" is one WHERE clause, on this box or a future control plane.
type WebRule struct {
	ent.Schema
}

func (WebRule) Fields() []ent.Field {
	return []ent.Field{
		field.Enum("kind").
			Values("proxy", "redirect", "alias"),
		// Location path for proxy/alias, match pattern for redirect.
		field.String("path").
			NotEmpty(),
		// Proxy: backend URL (private targets only in v1, validated at
		// the API). Redirect: destination URL. Alias: filesystem path.
		field.String("target").
			NotEmpty(),
		// Proxy behavior flags; meaningless (and false) for other kinds.
		// These replace the legacy #flag,flag URL-fragment hacks in
		// custom.yaml (pass-http-host, no-proxy-redirect,
		// frame-options-sameorigin, web-sockets).
		field.Bool("pass_host_header").
			Default(false),
		field.Bool("no_proxy_redirect").
			Default(false),
		field.Bool("frame_same_origin").
			Default(false),
		field.Bool("web_sockets").
			Default(false),
	}
}

func (WebRule) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("domain", WebDomain.Type).
			Ref("rules").
			Unique().
			Required(),
	}
}

func (WebRule) Indexes() []ent.Index {
	return []ent.Index{
		// One rule per path per domain: two rules on the same path
		// would fight over one nginx location.
		index.Fields("path").
			Edges("domain").
			Unique(),
	}
}
