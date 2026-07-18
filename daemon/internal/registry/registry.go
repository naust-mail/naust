// Package registry is the manager-side catalog of the box's services:
// the identity and addressing facts (backend host/port, enabling flag,
// where the app may be mounted) that would otherwise end up duplicated
// across the web renderer, mount validation, and status checks.
//
// Scope limits, deliberately:
//
//   - Identity and addressing only. The registry does NOT own lifecycle:
//     what gets installed (setup/components), what runs (systemd units,
//     docker compose profiles), or what the setup wizard asks. A service
//     can be correctly defined here and still be wired wrong in those
//     independent systems.
//   - A field is added only when it has two or more real consumers today,
//     never speculatively.
//   - The registry MUST NOT feed helperd's allowlists. The privileged
//     helper keeps its own closed, hardcoded vocabulary; tests may assert
//     consistency between the two one-way, but the trust boundary never
//     inverts.
//   - Renderer details (nginx snippets, per-app base-path knobs) are not
//     registry data; they live in the consumers, keyed by Name.
package registry

// Flag gates an optional service on one naust.conf / environment
// variable. The service is enabled when the variable's value (or Default
// when it is unset) equals Value. The zero Flag means "always enabled".
type Flag struct {
	Var     string
	Value   string
	Default string
	// DockerDefault overrides Default when RUNTIME=docker. Empty means no
	// override. Exists because "no MONITORING_TOOL set" means two
	// different things by runtime: on bare metal it is a legacy box that
	// already has munin installed; in Docker it is a fresh box where
	// munin was never even installed unless its compose profile was
	// started explicitly.
	DockerDefault string
}

// Service describes one service the manager needs to address or place.
type Service struct {
	// Name is the canonical id, e.g. "filebrowser", "webmail-rav".
	Name string

	// Role is the mount slot the service fills. Alternatives that are
	// selected by the same flag (the webmail clients, the monitoring
	// tools) share a role, and at most one of them is enabled at a
	// time. Empty means the service is its own role.
	Role string

	// EnabledWhen gates optional services; the zero value = always on.
	EnabledWhen Flag

	// HostEnv is the environment variable carrying the backend host
	// (docker compose overrides it to a container name; bare metal
	// leaves it unset and 127.0.0.1 applies). Empty with Port set
	// means the backend is loopback-only. Empty with Port zero means
	// the service is not an HTTP proxy backend (PHP apps run through
	// the local FPM socket instead).
	HostEnv string

	// Port is the backend TCP port the web tier proxies to.
	Port int

	// MountRoot and MountPath say where an admin may place the app on
	// the primary hostname: at "/" and/or at a chosen subpath. Both
	// false means the app's location is fixed at DefaultMount and the
	// panel cannot move it.
	MountRoot bool
	MountPath bool

	// DefaultMount is where the app lives when the admin has not
	// chosen otherwise ("/" for root), or its fixed location when it
	// is not placeable.
	DefaultMount string
}

// RoleName returns Role, defaulting to Name.
func (s Service) RoleName() string {
	if s.Role != "" {
		return s.Role
	}
	return s.Name
}

// Enabled reports whether the service is on, given a lookup for
// naust.conf / environment values (empty string = unset).
func (s Service) Enabled(get func(string) string) bool {
	if s.EnabledWhen.Var == "" {
		return true
	}
	v := get(s.EnabledWhen.Var)
	if v == "" {
		v = s.EnabledWhen.Default
		if s.EnabledWhen.DockerDefault != "" && get("RUNTIME") == "docker" {
			v = s.EnabledWhen.DockerDefault
		}
	}
	return v == s.EnabledWhen.Value
}

// services is the table. Backend facts trace to the nginx templates in
// setup/conf/nginx/ and the env defaults in web_update.py. Mount
// capabilities start conservative: MountPath is only true where the app
// is known to work under a subpath; flipping one to true later is safe,
// the reverse strands existing configs.
var services = []Service{
	{
		// The admin panel is the recovery path when a mount change
		// goes wrong, so it is never placeable.
		Name:         "admin",
		HostEnv:      "MANAGEMENT_HOST",
		Port:         10223,
		DefaultMount: "/admin",
	},
	{
		// Base-path support in the rav SPA is unverified;
		// root-only until it is.
		Name:         "webmail-rav",
		Role:         "webmail",
		EnabledWhen:  Flag{Var: "WEBMAIL_CLIENT", Value: "rav", Default: "rav"},
		HostEnv:      "WEBMAIL_HOST",
		Port:         3001,
		MountRoot:    true,
		DefaultMount: "/",
	},
	{
		// PHP apps are root-only for now: their nginx blocks hardcode
		// the document root and fastcgi script paths, and no subpath
		// (alias-based) variant exists yet.
		Name:         "webmail-roundcube",
		Role:         "webmail",
		EnabledWhen:  Flag{Var: "WEBMAIL_CLIENT", Value: "roundcube", Default: "rav"},
		MountRoot:    true,
		DefaultMount: "/",
	},
	{
		Name:         "webmail-snappymail",
		Role:         "webmail",
		EnabledWhen:  Flag{Var: "WEBMAIL_CLIENT", Value: "snappymail", Default: "rav"},
		MountRoot:    true,
		DefaultMount: "/",
	},
	{
		// Subpath support unverified; root-only until it is.
		Name:         "webmail-cypht",
		Role:         "webmail",
		EnabledWhen:  Flag{Var: "WEBMAIL_CLIENT", Value: "cypht", Default: "rav"},
		MountRoot:    true,
		DefaultMount: "/",
	},
	{
		// filebrowser has a baseurl setting, so it can live anywhere.
		Name:         "filebrowser",
		EnabledWhen:  Flag{Var: "ENABLE_FILEBROWSER", Value: "true", Default: "true"},
		HostEnv:      "FILEBROWSER_HOST",
		Port:         8080,
		MountRoot:    true,
		MountPath:    true,
		DefaultMount: "/files",
	},
	{
		// CalDAV/CardDAV clients and the well-known redirects assume
		// this path; fixed.
		Name:         "radicale",
		EnabledWhen:  Flag{Var: "ENABLE_RADICALE", Value: "true", Default: "true"},
		HostEnv:      "RADICALE_HOST",
		Port:         5232,
		DefaultMount: "/radicale",
	},
	{
		Name:         "netdata",
		Role:         "monitoring",
		EnabledWhen:  Flag{Var: "MONITORING_TOOL", Value: "netdata", Default: "munin"},
		Port:         19999,
		DefaultMount: "/admin/netdata",
	},
	{
		Name:         "beszel",
		Role:         "monitoring",
		EnabledWhen:  Flag{Var: "MONITORING_TOOL", Value: "beszel", Default: "munin"},
		HostEnv:      "BESZEL_HUB_HOST",
		Port:         8090,
		DefaultMount: "/admin/beszel",
	},
	{
		// Munin has no web server of its own; muninweb (cmd/muninweb,
		// installed by the munin setup component) serves the
		// cron-rendered site and graph CGI on loopback. The role
		// default is munin because a box without MONITORING_TOOL set
		// is a legacy munin box (same default as the setup component).
		// DockerDefault overrides that to "none": a fresh Docker box
		// never has munin installed unless its compose profile was
		// started explicitly.
		Name:         "munin",
		Role:         "monitoring",
		EnabledWhen:  Flag{Var: "MONITORING_TOOL", Value: "munin", Default: "munin", DockerDefault: "none"},
		HostEnv:      "MUNIN_HOST",
		Port:         4948,
		DefaultMount: "/admin/munin",
	},
}

// All returns the full table, copied so callers cannot mutate it.
func All() []Service {
	out := make([]Service, len(services))
	copy(out, services)
	return out
}

// ByName looks a service up by its canonical id.
func ByName(name string) (Service, bool) {
	for _, s := range services {
		if s.Name == name {
			return s, true
		}
	}
	return Service{}, false
}

// ByRole returns every service filling the given mount slot.
func ByRole(role string) []Service {
	var out []Service
	for _, s := range services {
		if s.RoleName() == role {
			out = append(out, s)
		}
	}
	return out
}
