package helper

import "os"

// Closed vocabularies for every intent. Nothing here is caller-extensible;
// unknown names are rejected before any command runs.

// serviceDef describes one service the helper may act on.
type serviceDef struct {
	// reload is a custom reload command sequence. nil means
	// "systemctl reload <name>".
	reload [][]string
	// reloadFallback runs if the custom reload sequence fails. nil means
	// the reload error is returned as-is.
	reloadFallback []string
}

// Custom sequences are copied verbatim from _BARE_METAL_RELOAD / _BARE_METAL_RELOAD_FALLBACK.
var services = map[string]serviceDef{
	"nsd": {
		reload: [][]string{
			{"/usr/sbin/nsd-control", "reconfig"},
			{"/usr/sbin/nsd-control", "reload"},
		},
		reloadFallback: []string{"/usr/bin/systemctl", "restart", "nsd"},
	},
	// unbound cache flush is expressed as a "reload" at the caller level.
	"unbound": {
		reload: [][]string{
			{"/usr/sbin/unbound-control", "-c", "/etc/unbound/unbound.conf", "flush_zone", "."},
		},
	},
	"postfix":     {},
	"dovecot":     {},
	"opendkim":    {},
	"opendmarc":   {},
	"spampd":      {},
	"nginx":       {},
	"filebrowser": {},
	"rav":         {},
}

// KnownService reports whether name is in the helper's closed service
// vocabulary. Exported for one-way drift tests only: managerd callers
// that hardcode service names assert them against this, so a rename
// here (or a new caller naming a service the helper refuses) fails in
// CI instead of at runtime on a box. The vocabulary itself must never
// be derived from caller-side data - the trust boundary points the
// other way.
func KnownService(name string) bool {
	_, ok := services[name]
	return ok
}

// postfixKeys are the only main.cf parameters postfix.set may touch -
// exactly the relay parameters the daemon manages today
var postfixKeys = map[string]bool{
	"relayhost":                  true,
	"smtp_sasl_auth_enable":      true,
	"smtp_sasl_password_maps":    true,
	"smtp_sasl_security_options": true,
	"smtp_tls_security_level":    true,
}

// configTarget is one named file config.write may replace. The path and
// mode are baked in here; callers never supply paths.
type configTarget struct {
	path string
	mode os.FileMode
}

var configTargets = map[string]configTarget{
	"nginx_local": {path: "/etc/nginx/conf.d/local.conf", mode: 0o644},
}

// There is deliberately no postfix.map intent: the only Postfix lookup
// table the daemon manages (relay sasl_passwd) lives on STORAGE_ROOT,
// which the manager owns - it writes the file and runs postmap itself,
// unprivileged. Per the ownership-vs-intent rule, only root-parsed
// config (main.cf via postfix.set) needs the helper.
