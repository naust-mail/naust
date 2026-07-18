// Package checks is the status-check engine: it evaluates the box's
// health by diffing desired state (the store, the appliers' outputs)
// against the observed world (local services, DNS, the network) and
// persists structured verdicts.
//
// The package is a library on purpose. managerd links it and runs it
// unprivileged behind /api/system/checks; a future boxctl doctor
// links the same package and runs it in-process as root, gaining the
// root-only checks with no RPC and no dependency on the daemon being
// alive. Deps.RootContext tells checks which world they are in, and
// each check declares a Locus so a future multi-node split (world
// checks on the control plane, node checks in per-node agents) is a
// routing decision, not a rewrite.
//
// Scheduling is tiered: every check has a default cadence (its Tier)
// that the administrator can override per check, including disabling
// it, via the status_checks setting. Results are store rows, one per
// (check, domain): the panel always reads the latest snapshot
// instantly and never waits for a run.
package checks

import (
	"context"
	"log"
	"net"
	"net/http"
	"time"

	dnszone "naust/daemon/internal/dns"
	"naust/daemon/internal/store/ent"
)

// Status of a check or a step, ordered by severity for summarizing.
type Status string

const (
	StatusOK      Status = "ok"
	StatusSkipped Status = "skipped"
	StatusWarning Status = "warning"
	StatusError   Status = "error"
)

// severity orders statuses for worst-of summaries.
func severity(s Status) int {
	switch s {
	case StatusError:
		return 3
	case StatusWarning:
		return 2
	case StatusOK:
		return 1
	}
	return 0
}

// Tier is a check's default cadence. Administrators can override the
// cadence per check (including "weekly" and "off", which exist only
// as overrides) in the status_checks setting.
type Tier string

const (
	TierFast   Tier = "fast"   // ~5 minutes: cheap local probes whose failures are urgent
	TierHourly Tier = "hourly" // external state that drifts slowly (DNS, certs)
	TierDaily  Tier = "daily"  // rate-limited or slow-moving lookups (RBLs, apt)
)

// Class says how a check's success is presented. Standard checks
// always render. Quiet checks verify invariants the software itself
// maintains - their success carries no information, so the panel
// hides them behind a "background checks passing" line and they only
// surface on warning or error. Metric checks carry a number worth
// glancing at even when green (disk usage, backup age).
type Class string

const (
	ClassStandard Class = "standard"
	ClassQuiet    Class = "quiet"
	ClassMetric   Class = "metric"
)

// Locus says where a check must execute in a multi-node deployment:
// on the node it inspects, or anywhere with a network view of the
// world. Single-box deployments ignore it.
type Locus string

const (
	LocusNode  Locus = "node"
	LocusWorld Locus = "world"
)

// Step is one phase of a check's run, the unit the panel renders like
// a CI job step. Expected and Observed carry the structured diff when
// the step compared something; FixHint tells the operator (or a
// future fix button) what would repair it.
type Step struct {
	Name      string `json:"name"`
	Status    Status `json:"status"`
	Message   string `json:"message,omitempty"`
	Expected  string `json:"expected,omitempty"`
	Observed  string `json:"observed,omitempty"`
	FixHint   string `json:"fix_hint,omitempty"`
	ElapsedMs int64  `json:"elapsed_ms"`
}

// Result is the outcome of one check run (one domain instance for
// per-domain checks).
type Result struct {
	Check    string
	Category string
	Domain   string
	Status   Status
	Message  string
	Steps    []Step
	RanAt    time.Time
	Elapsed  time.Duration
}

// Check is one registered status check.
type Check struct {
	// Name is the stable id ("free-disk-space", "service:postfix").
	// It keys stored results and failure history; it never changes.
	Name string
	// Title is the human name the panel shows ("Free disk space").
	// Reword freely - history keys off Name. Empty falls back to Name.
	Title string
	// ShortLabel is the one-word tag for a metric check's inline badge
	// on the collapsed doctor category line ("disk", "backup"). Only
	// metric-class checks need it; empty falls back to a shortened Title.
	ShortLabel string
	// Description says what the check verifies and why an operator
	// should care, in plain language, one or two sentences. Static:
	// what is wrong right now belongs in the run's message, not here.
	Description string
	// Class drives success presentation; the zero value renders
	// standard (always visible).
	Class Class
	// Category groups checks for the panel: system, services,
	// network, dns, mail, web.
	Category string
	Locus    Locus
	Tier     Tier
	// Timeout overrides the engine's per-check timeout when nonzero.
	Timeout time.Duration
	// DependsOn names checks whose latest result gates this one: if a
	// dependency's latest status is error, this check is recorded as
	// skipped instead of running (the unbound pattern - do not hammer
	// DNS lookups when the resolver itself is down).
	DependsOn []string
	// Enabled reports whether the check applies to this box at all
	// (spam-filter variants, docker exclusions). Nil means always.
	// Distinct from the admin's config override, which the engine
	// handles.
	Enabled func(d *Deps) bool
	// Domains expands a per-domain check into one run per domain.
	// Nil means the check runs once with an empty domain.
	Domains func(ctx context.Context, d *Deps) ([]string, error)
	// Run performs the check, reporting through r. Step failures do
	// not abort the run: later steps still execute, so one result
	// shows every phase like a CI job.
	Run func(ctx context.Context, d *Deps, domain string, r *Reporter)
}

// Deps carries everything checks read or call, with seams for tests.
// Nil function fields are filled with real implementations by
// (*Engine).Start / NewEngine.
type Deps struct {
	Store           *ent.Client
	Conf            func(key string) string // boxconf lookup; nil reads as unset
	PrimaryHostname string
	PublicIP        string
	PublicIPv6      string
	StorageRoot     string
	// MapsDir is where the materializer renders the mail routing
	// tables. Empty disables checks that read them.
	MapsDir string

	// RootContext is true when the process runs as root (boxctl
	// doctor); managerd leaves it false and root-only checks report
	// that they cannot verify from here.
	RootContext bool
	// InDocker disables host-level checks that the container model
	// makes meaningless (ufw, ssh, timedatectl).
	InDocker bool

	// Dial probes TCP services. Defaults to a net.Dialer with a
	// short timeout.
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
	// HTTP performs health-endpoint requests. Defaults to a client
	// with a short timeout.
	HTTP *http.Client
	// Run executes a local command and returns its combined output.
	// The error carries the output when the command fails.
	Run func(ctx context.Context, argv ...string) (string, error)
	// ReadFile reads host files (/proc/meminfo, sshd_config).
	// Defaults to os.ReadFile.
	ReadFile func(name string) ([]byte, error)
	// Zones returns the desired DNS zones (dnsapply DesiredZones).
	// Nil disables every DNS check - there is nothing to diff against.
	Zones func(ctx context.Context) ([]dnszone.Zone, error)
	// AuthFailures returns the cumulative count of failed logins
	// across all replicas (the store-backed auth-failure counter
	// httpapi increments). Nil disables the login-failure heuristic.
	AuthFailures func(ctx context.Context) (int64, error)
	// PostfixQueue returns postqueue -j output. managerd routes this
	// through the root helper: NoNewPrivileges strips postqueue's
	// setgid bit for the daemon's children, so the direct call can
	// never read the showq socket there. Nil falls back to running
	// postqueue via Run (root contexts, tests).
	PostfixQueue func(ctx context.Context) (string, error)
	// SMTPAddr is where the report digest is submitted (the mail
	// container in Docker). Empty means localhost:25.
	SMTPAddr string
	// SendMail overrides digest submission entirely (tests). Nil uses
	// SMTP to SMTPAddr.
	SendMail func(ctx context.Context, to, subject, body string) error
	// Query performs one DNS query against a chosen server. Defaults
	// to a miekg/dns exchange with a short timeout.
	Query func(ctx context.Context, q DNSQuery) (*DNSReply, error)

	Now func() time.Time
	Log *log.Logger
}

func (d *Deps) conf(key string) string {
	if d.Conf == nil {
		return ""
	}
	return d.Conf(key)
}

// flag reads a naust.conf value with a default, mirroring
// registry.Flag semantics.
func (d *Deps) flag(key, def string) string {
	if v := d.conf(key); v != "" {
		return v
	}
	return def
}
