// Package webrender renders nginx configuration from the routing table:
// the semantic web state (hosts, app mounts, customization rules) goes
// in, a set of per-hostname config files comes out. The renderer is pure -
// no filesystem, no environment, no store access. Callers resolve
// everything (cert paths, backend hosts, enabled mounts) first; in
// particular, mounts referencing disabled or absent apps must be
// filtered out by the caller, so the renderer never proxies to a dead
// backend.
//
// This is the shared, trusted boundary renderer, imported by BOTH the
// unprivileged manager (which builds the routing model from the store)
// and the privileged helper (which runs Render on it). Rendering happens
// on the helper side so the manager can supply only field values, never
// nginx directives - so every input field is validated here (see the
// validators below) because nginx parses this output as root.
//
// The stored model stays backend-neutral (see web-slice design); all
// nginx knowledge lives here. Every generated file starts with
// ManagedMark, which is how the sync intent tells our files from
// user-owned ones it must never touch.
package webrender

import (
	"fmt"
	"regexp"
	"strings"
)

// ManagedMark is the first line of every generated file. The helper's
// sync intent only ever overwrites or deletes files carrying it.
const ManagedMark = "# MANAGED BY naust-web - do not edit; regenerated on every apply."

// TemplateVersion stamps generated files. Ejected copies keep their
// stamp, so the panel can warn when our templates have moved on.
const TemplateVersion = 1

// TopFile is the fixed name of the http-level preamble file (the
// WebSocket Connection-header map used by proxy mounts).
const TopFile = "00-top.conf"

// Config carries box-level values the renderer cannot know itself.
type Config struct {
	// ACMEWebroot is where the cert provisioner stores ACME HTTP-01
	// challenge responses, e.g. STORAGE_ROOT/ssl/lets_encrypt/webroot.
	ACMEWebroot string
	// PHPSocket is the PHP-FPM unix socket path, used by the PHP
	// webmail clients (roundcube, snappymail, cypht).
	PHPSocket string
}

// Host is one hostname's fully resolved web state.
type Host struct {
	Domain string
	// Primary marks the box's primary hostname: it becomes nginx's
	// default_server and is the only host that carries app mounts.
	Primary bool

	CertFile string
	KeyFile  string
	// CertHash is a fingerprint of the key+cert contents, embedded as
	// a comment so a renewed cert changes the file and forces a sync.
	CertHash string

	// RedirectTo, when set, makes the HTTPS vhost a bare permanent
	// redirect to that domain (the default www.* handling). All other
	// content fields are ignored.
	RedirectTo string

	// Root is the static-file directory; empty means the host serves
	// no static files (system paths and rules still apply).
	Root string
	// HSTS is the Strict-Transport-Security level: on, preload, off.
	HSTS string
	// Include is the absolute path of a user-owned nginx include file
	// merged into the vhost, or empty. The raw server-side hatch.
	Include string

	Mounts []Mount
	Rules  []Rule
}

// Mount places an app (a registry service) at a path on the host.
type Mount struct {
	// App is the registry service name; it selects the location-block
	// shape (proxy vs PHP vs auth-gated) and is validated by Render.
	App string
	// Path is the mount point: "/" for a root catch-all, otherwise a
	// prefix like /files (no trailing slash).
	Path string
	// BackendHost and BackendPort are the resolved proxy target for
	// proxy-backed apps; unused for the PHP webmail clients.
	BackendHost string
	BackendPort int
	// AuthUser is the trusted identity header value for apps that
	// auto-login a fixed account (beszel's X-Beszel-User).
	AuthUser string
}

// Rule is one customization rule from the store (WebRule row).
type Rule struct {
	Kind   string // proxy, redirect, alias
	Path   string
	Target string
	// Proxy flags; false for other kinds.
	PassHostHeader  bool
	NoProxyRedirect bool
	FrameSameOrigin bool
	WebSockets      bool
}

// SyncPayload is what the manager sends to helperd's web.sync_sites
// intent: the routing model, never rendered nginx. helperd renders it on
// the privileged side (see internal/helper/websync.go), so a compromised
// manager can supply only field values, never nginx directives.
type SyncPayload struct {
	Config Config
	Hosts  []Host
}

var safeDomain = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]*$`)

// Field validators. The renderer is the trust boundary: it runs on the
// privileged side (helperd) against input from the unprivileged manager,
// so every value it interpolates into a directive must be checked here.
// A value that could end a directive early (";"), open or close a block
// ("{}"), start a new line, or smuggle a variable ("$") would otherwise
// let the caller inject arbitrary nginx - which nginx parses as root.

// safePath accepts an absolute path in a conservative charset. Every
// path the renderer emits (cert files, roots, sockets, the ACME
// webroot) fits; anything with a directive-breaking or whitespace
// character is rejected.
func safePath(s string) bool {
	if s == "" || s[0] != '/' {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '/' || r == '.' || r == '_' || r == '-':
		default:
			return false
		}
	}
	return true
}

// safeHost accepts a hostname or IPv4 literal used as a proxy backend.
func safeHost(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '.' || r == '-' || r == '_':
		default:
			return false
		}
	}
	return true
}

// safeURLPath accepts a mount point: an absolute URL path or a bare "/".
func safeURLPath(s string) bool {
	if s == "" || s[0] != '/' {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '/' || r == '.' || r == '_' || r == '-' || r == '~':
		default:
			return false
		}
	}
	return true
}

// safeToken accepts a value going into a quoted header (AuthUser).
func safeToken(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '@' || r == '.' || r == '_' || r == '-':
		default:
			return false
		}
	}
	return true
}

// noControl rejects control characters (a newline in a comment value
// like CertHash would otherwise escape the comment).
func noControl(s string) bool {
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

// validate checks the renderer configuration.
func (c Config) validate() error {
	if !safePath(c.ACMEWebroot) {
		return fmt.Errorf("unsafe ACME webroot %q", c.ACMEWebroot)
	}
	// PHPSocket may be empty on hosts with no PHP webmail; appBlock
	// rejects an empty socket for the apps that need it.
	if c.PHPSocket != "" && !safePath(c.PHPSocket) {
		return fmt.Errorf("unsafe PHP socket %q", c.PHPSocket)
	}
	return nil
}

// validate checks every host field the renderer interpolates.
func (h Host) validate() error {
	if !safeDomain.MatchString(h.Domain) {
		return fmt.Errorf("unsafe domain name %q", h.Domain)
	}
	if !safePath(h.CertFile) {
		return fmt.Errorf("unsafe cert file %q", h.CertFile)
	}
	if !safePath(h.KeyFile) {
		return fmt.Errorf("unsafe key file %q", h.KeyFile)
	}
	if !noControl(h.CertHash) {
		return fmt.Errorf("unsafe cert hash")
	}
	if h.RedirectTo != "" && !safeDomain.MatchString(h.RedirectTo) {
		return fmt.Errorf("unsafe redirect target %q", h.RedirectTo)
	}
	if h.Root != "" && !safePath(h.Root) {
		return fmt.Errorf("unsafe root %q", h.Root)
	}
	if h.Include != "" && !safePath(h.Include) {
		return fmt.Errorf("unsafe include path %q", h.Include)
	}
	for _, m := range h.Mounts {
		if !safeURLPath(m.Path) {
			return fmt.Errorf("unsafe mount path %q", m.Path)
		}
		if m.BackendHost != "" && !safeHost(m.BackendHost) {
			return fmt.Errorf("unsafe backend host %q", m.BackendHost)
		}
		if m.BackendPort < 0 || m.BackendPort > 65535 {
			return fmt.Errorf("backend port %d out of range", m.BackendPort)
		}
		if m.AuthUser != "" && !safeToken(m.AuthUser) {
			return fmt.Errorf("unsafe auth user %q", m.AuthUser)
		}
	}
	return nil
}

// Render produces the complete managed fileset: TopFile plus one
// "<domain>.conf" per host. Deterministic for identical input, so the
// applier can hash the result for change detection.
func Render(cfg Config, hosts []Host) (map[string]string, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	files := map[string]string{TopFile: renderTop()}
	for _, h := range hosts {
		if err := h.validate(); err != nil {
			return nil, err
		}
		fn := h.Domain + ".conf"
		if _, dup := files[fn]; dup {
			return nil, fmt.Errorf("duplicate host %s", h.Domain)
		}
		content, err := renderHost(cfg, h)
		if err != nil {
			return nil, fmt.Errorf("host %s: %w", h.Domain, err)
		}
		files[fn] = content
	}
	return files, nil
}

func header() string {
	return fmt.Sprintf("%s\n# template-version: %d\n\n", ManagedMark, TemplateVersion)
}

func renderTop() string {
	var b strings.Builder
	b.WriteString(header())
	b.WriteString(`# Sets the Connection header only on WebSocket upgrade requests,
# and close on all others. Used by proxy location blocks.
map $http_upgrade $connection_upgrade {
	default upgrade;
	''      close;
}

# Caps raw request rate to /api/auth/login (see adminBlock in apps.go) per
# source IP - that endpoint spends a deliberate, real bcrypt cost on every
# call (including failed logins, to prevent account-enumeration by timing),
# so an unthrottled flood can pin CPU. The 1r/s steady-state rate is what
# actually bounds sustained CPU cost (an attacking IP can never sustain more
# than ~1 hash/sec no matter how large its initial burst); adminBlock's
# burst=20 only absorbs a simultaneous spike - several admins behind the
# same office NAT/VPN egress logging in around the same moment - without a
# false 429, it does not raise the long-run ceiling. Deliberately looser
# than fail2ban's own auth-failure-based ban (20 failures/30s, the
# naust-management jail): this exists purely to bound raw flood rate, not
# to replace fail2ban's slower, failure-counting brute-force detection.
# limit_req_status matches the nginx-ratelimit fail2ban filter, which
# escalates repeated 429s from any source into a full ban.
limit_req_zone $binary_remote_addr zone=login:10m rate=1r/s;
limit_req_status 429;
`)
	return b.String()
}

func renderHost(cfg Config, h Host) (string, error) {
	var b strings.Builder
	b.WriteString(header())
	fmt.Fprintf(&b, "## %s\n\n", h.Domain)

	// Port 80: always ours on every host - HTTPS redirect plus the
	// ACME challenge webroot, so cert renewal can never break.
	b.WriteString("server {\n")
	b.WriteString("\tlisten 80;\n\tlisten [::]:80;\n\n")
	fmt.Fprintf(&b, "\tserver_name %s;\n", h.Domain)
	b.WriteString("\troot /tmp/invalid-path-nothing-here;\n")
	b.WriteString("\tserver_tokens off;\n\n")
	fmt.Fprintf(&b, "\tlocation / {\n\t\treturn 301 https://%s$request_uri;\n\t}\n\n", h.Domain)
	// Served over HTTP per the ACME spec.
	fmt.Fprintf(&b, "\tlocation /.well-known/acme-challenge/ {\n\t\talias %s/.well-known/acme-challenge/;\n\t}\n", cfg.ACMEWebroot)
	b.WriteString("}\n\n")

	// Port 443.
	b.WriteString("server {\n")
	def := ""
	if h.Primary {
		def = " default_server"
	}
	// listen-line http2: the standalone "http2 on;" directive needs nginx
	// 1.25+, which Ubuntu 22.04/24.04 do not ship. The listen form works on
	// every supported version (deprecation notice on new nginx is accepted).
	fmt.Fprintf(&b, "\tlisten 443 ssl http2%s;\n\tlisten [::]:443 ssl http2%s;\n\n", def, def)
	fmt.Fprintf(&b, "\tserver_name %s;\n", h.Domain)
	b.WriteString("\tserver_tokens off;\n\n")
	fmt.Fprintf(&b, "\tssl_certificate %s;\n", h.CertFile)
	fmt.Fprintf(&b, "\tssl_certificate_key %s;\n", h.KeyFile)
	if h.CertHash != "" {
		fmt.Fprintf(&b, "\t# ssl files hash: %s\n", h.CertHash)
	}
	b.WriteString("\n")

	if h.RedirectTo != "" {
		fmt.Fprintf(&b, "\trewrite ^(.*) https://%s$1 permanent;\n", h.RedirectTo)
		b.WriteString("}\n")
		return b.String(), nil
	}

	if h.Root != "" {
		fmt.Fprintf(&b, "\troot %s;\n", h.Root)
		b.WriteString("\tindex index.html index.htm;\n\n")
	}
	systemLocations(&b)

	mounted := map[string]bool{}
	for _, m := range h.Mounts {
		if !h.Primary {
			return "", fmt.Errorf("mount %s on non-primary host", m.App)
		}
		if mounted[m.App] {
			return "", fmt.Errorf("app %s mounted twice", m.App)
		}
		mounted[m.App] = true
		if err := appBlock(&b, cfg, m); err != nil {
			return "", err
		}
	}
	for _, r := range h.Rules {
		// Defense in depth behind the API's validation: a path or
		// target smuggling nginx syntax could inject directives that
		// pass nginx -t (";" ends a directive mid-line). Panel admins
		// are not root, so this boundary matters.
		if strings.ContainsAny(r.Path+r.Target, ";{}\"'\n\r\t ") || r.Path == "" || r.Target == "" {
			return "", fmt.Errorf("unsafe rule %s %q -> %q", r.Kind, r.Path, r.Target)
		}
		ruleBlock(&b, r)
	}

	switch h.HSTS {
	case "on":
		b.WriteString("\tadd_header Strict-Transport-Security \"max-age=15768000\" always;\n\n")
	case "preload":
		b.WriteString("\tadd_header Strict-Transport-Security \"max-age=15768000; includeSubDomains; preload\" always;\n\n")
	case "off":
	default:
		return "", fmt.Errorf("unknown hsts level %q", h.HSTS)
	}

	if h.Include != "" {
		fmt.Fprintf(&b, "\tinclude %s;\n\n", h.Include)
	}

	// Disable viewing dotfiles (.htaccess, .git, etc.). Placed last:
	// regex locations match in order, so app and rule regex blocks
	// above still win for their own patterns.
	b.WriteString("\tlocation ~ /\\.(ht|svn|git|hg|bzr) {\n")
	b.WriteString("\t\tlog_not_found off;\n\t\taccess_log off;\n\t\tdeny all;\n\t}\n")
	b.WriteString("}\n")
	return b.String(), nil
}

// systemLocations are the mail-infrastructure paths every non-redirect
// host serves: client autoconfiguration and the MTA-STS policy.
func systemLocations(b *strings.Builder) {
	b.WriteString(`	location = /robots.txt {
		log_not_found off;
		access_log off;
	}

	location = /favicon.ico {
		log_not_found off;
		access_log off;
	}

	location = /naust.mobileconfig {
		alias /var/lib/naust/mobileconfig.xml;
	}
	location = /.well-known/autoconfig/mail/config-v1.1.xml {
		alias /var/lib/naust/mozilla-autoconfig.xml;
	}
	location = /mail/config-v1.1.xml {
		alias /var/lib/naust/mozilla-autoconfig.xml;
	}
	location = /.well-known/mta-sts.txt {
		alias /var/lib/naust/mta-sts.txt;
	}

`)
}

func ruleBlock(b *strings.Builder, r Rule) {
	switch r.Kind {
	case "proxy":
		fmt.Fprintf(b, "\tlocation %s {\n", r.Path)
		fmt.Fprintf(b, "\t\tproxy_pass %s;\n", r.Target)
		if r.NoProxyRedirect {
			b.WriteString("\t\tproxy_redirect off;\n")
		}
		if r.PassHostHeader {
			b.WriteString("\t\tproxy_set_header Host $http_host;\n")
		}
		if r.FrameSameOrigin {
			b.WriteString("\t\tproxy_set_header X-Frame-Options SAMEORIGIN;\n")
		}
		if r.WebSockets {
			b.WriteString("\t\tproxy_http_version 1.1;\n")
			b.WriteString("\t\tproxy_set_header Upgrade $http_upgrade;\n")
			b.WriteString("\t\tproxy_set_header Connection 'Upgrade';\n")
		}
		b.WriteString("\t\tproxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n")
		b.WriteString("\t\tproxy_set_header X-Forwarded-Host $http_host;\n")
		b.WriteString("\t\tproxy_set_header X-Forwarded-Proto $scheme;\n")
		b.WriteString("\t\tproxy_set_header X-Real-IP $remote_addr;\n")
		b.WriteString("\t}\n\n")
	case "alias":
		fmt.Fprintf(b, "\tlocation %s {\n\t\talias %s;\n\t}\n\n", r.Path, r.Target)
	case "redirect":
		fmt.Fprintf(b, "\trewrite %s %s permanent;\n\n", r.Path, r.Target)
	}
}
