package checks

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"naust/daemon/internal/registry"
)

// probe is one TCP service the box must be running. Core services are
// listed here; optional HTTP apps come from internal/registry so their
// enabling flags and ports have one home.
type probe struct {
	// ID is the stable check-name suffix; Label the human name used
	// in messages.
	ID, Label string
	// HostVar is the naust.conf variable Docker overrides with a
	// container name; empty or unset falls back to 127.0.0.1.
	HostVar string
	Port    int
	// Public services must answer on the box's public addresses;
	// private ones on their backend address.
	Public  bool
	Enabled func(d *Deps) bool
}

func isRspamd(d *Deps) bool       { return d.flag("SPAM_FILTER", "rspamd") == "rspamd" }
func isSpamassassin(d *Deps) bool { return d.flag("SPAM_FILTER", "rspamd") == "spamassassin" }

// probeTable is the box's network surface. The management daemon
// itself is deliberately absent: these results existing at all proves
// it runs.
func probeTable(d *Deps) []probe {
	table := []probe{
		// LMTP has no authentication of its own - it is the trusted
		// internal handoff from Postfix to Dovecot, deliberately kept on
		// loopback (see dovecot.py). In Docker that means it is only
		// ever reachable from inside the mail container itself, so
		// probing it cross-container from managerd would either always
		// fail by design or require opening an unauthenticated protocol
		// to the network - neither is worth it just to satisfy a check.
		{ID: "lmtp", Label: "Dovecot LMTP LDA", HostVar: "MAIL_HOST", Port: 10026, Enabled: notDocker},
		{ID: "ssh", Label: "SSH Login (ssh)", Port: sshPort(d), Public: true, Enabled: notDocker},
		{ID: "nsd", Label: "Public DNS (nsd)", HostVar: "DNS_HOST", Port: nsdPort(d), Public: true},
		{ID: "smtp", Label: "Incoming Mail (SMTP/postfix)", HostVar: "MAIL_HOST", Port: 25, Public: true},
		{ID: "smtps", Label: "Outgoing Mail (SMTP 465/postfix)", HostVar: "MAIL_HOST", Port: 465, Public: true},
		{ID: "submission", Label: "Outgoing Mail (SMTP 587/postfix)", HostVar: "MAIL_HOST", Port: 587, Public: true},
		{ID: "imaps", Label: "IMAPS (dovecot)", HostVar: "MAIL_HOST", Port: 993, Public: true},
		{ID: "sieve", Label: "Mail Filters (Sieve/dovecot)", HostVar: "MAIL_HOST", Port: 4190, Public: true},
		{ID: "http", Label: "HTTP Web (nginx)", HostVar: "NGINX_HOST", Port: 80, Public: true},
		{ID: "https", Label: "HTTPS Web (nginx)", HostVar: "NGINX_HOST", Port: 443, Public: true},
		{ID: "rspamd", Label: "rspamd", HostVar: "RSPAMD_HOST", Port: 11332, Enabled: isRspamd},
		{ID: "redis", Label: "Redis", HostVar: "REDIS_HOST", Port: 6379, Enabled: isRspamd},
		{ID: "postgrey", Label: "Postgrey", HostVar: "MAIL_HOST", Port: 10023, Enabled: isSpamassassin},
		{ID: "spamassassin", Label: "Spamassassin", HostVar: "MAIL_HOST", Port: 10025, Enabled: isSpamassassin},
		{ID: "opendkim", Label: "OpenDKIM", HostVar: "MAIL_HOST", Port: 8891, Enabled: isSpamassassin},
		{ID: "opendmarc", Label: "OpenDMARC", HostVar: "MAIL_HOST", Port: 8893, Enabled: isSpamassassin},
	}
	// Optional HTTP backends: the registry knows their flags, hosts,
	// and ports. The admin panel is the daemon itself, skipped.
	for _, svc := range registry.All() {
		if svc.Port == 0 || svc.Name == "admin" {
			continue
		}
		svc := svc
		table = append(table, probe{
			ID: svc.Name, Label: svc.Name, HostVar: svc.HostEnv, Port: svc.Port,
			Enabled: func(d *Deps) bool { return svc.Enabled(d.conf) },
		})
	}
	return table
}

// nsdPort is nsd's listening port. In Docker, nsd and unbound share the
// "dns" container; the entrypoint moves nsd to 5353 to avoid clashing
// with unbound on port 53 (see the matching const in checks_dns.go).
// On bare metal they bind different addresses instead, so nsd stays on
// the standard port 53.
func nsdPort(d *Deps) int {
	if d.InDocker {
		return 5353
	}
	return 53
}

// sshPort reads the sshd Port directive, defaulting to 22.
func sshPort(d *Deps) int {
	if v, ok := sshdDirective(d, "port"); ok {
		var port int
		if _, err := fmt.Sscanf(v, "%d", &port); err == nil && port > 0 {
			return port
		}
	}
	return 22
}

func serviceChecks() []Check {
	checks := []Check{
		{
			// The local resolver is the dependency anchor: DNS-heavy
			// checks declare DependsOn: ["unbound"] and are skipped
			// while it is down instead of timing out one by one.
			Name:        "unbound",
			Title:       "Local DNS resolver",
			Description: "Confirms the box's own DNS resolver (unbound) is accepting connections on port 53. Many other checks and mail lookups rely on it, so they fail when it is down.",
			Category:    "services", Locus: LocusNode, Tier: TierFast,
			Run: func(ctx context.Context, d *Deps, _ string, r *Reporter) {
				r.Step("Local DNS (unbound) is running", func(s *StepCtx) {
					host := d.flag("DNS_HOST", "127.0.0.1")
					if !dialOK(ctx, d, host, 53) {
						s.Failf("Local DNS (unbound) is not running (port 53 on %s).", host)
						s.Hint("service.restart unbound")
						return
					}
					s.Passf("Local DNS (unbound) is accepting connections on port 53.")
				})
			},
		},
		{
			Name:        "fail2ban",
			Title:       "Intrusion blocker (fail2ban)",
			Description: "Confirms the service that blocks repeated failed logins (fail2ban) is running. Without it, password-guessing attempts are not blocked.",
			Category:    "services", Locus: LocusNode, Tier: TierFast,
			Enabled: notDocker,
			Run: func(ctx context.Context, d *Deps, _ string, r *Reporter) {
				r.Step("fail2ban is running", func(s *StepCtx) {
					out, err := d.Run(ctx, "systemctl", "is-active", "fail2ban")
					if err != nil || strings.TrimSpace(out) != "active" {
						s.Failf("fail2ban is not running.")
						s.Hint("service.restart fail2ban")
						return
					}
					s.Passf("fail2ban is active.")
				})
			},
		},
		{
			// helperd's postqueue call runs in the management container,
			// which shares no queue spool with the mail container in
			// Docker - it would read its own, always-empty spool and
			// silently report "queue is fine" during a real backlog.
			// Disabled there rather than shipping a false negative.
			Name:        "mail-queue",
			Title:       "Mail queue",
			ShortLabel:  "queue",
			Description: "Watches how many outgoing messages are waiting to be delivered. A queue that grows large means deliveries are failing or the box has started sending bulk mail.",
			Class:       ClassMetric,
			Category:    "services", Locus: LocusNode, Tier: TierFast,
			Enabled: notDocker,
			Run:     checkMailQueue,
		},
	}
	// One check per probe: a downed mail port must not hide whether
	// the web ports are up. The table is evaluated at registration
	// with a placeholder Deps only for naming, so registration is
	// stable regardless of configuration; hosts and enablement
	// resolve at run time.
	for _, p := range probeTable(&Deps{}) {
		id := p.ID
		checks = append(checks, Check{
			Name:        "service:" + id,
			Title:       p.Label,
			Description: "Confirms this network service is running and reachable on its expected port - on the box's public address for public services, on its backend address for internal ones. If it is unreachable, the mail or web function it provides stops working.",
			Category:    "services", Locus: LocusNode, Tier: TierFast,
			Enabled: func(d *Deps) bool { return probeByID(d, id).Port > 0 && probeEnabled(d, id) },
			Run: func(ctx context.Context, d *Deps, _ string, r *Reporter) {
				runProbe(ctx, d, probeByID(d, id), r)
			},
		})
	}
	return checks
}

func probeByID(d *Deps, id string) probe {
	for _, p := range probeTable(d) {
		if p.ID == id {
			return p
		}
	}
	return probe{}
}

func probeEnabled(d *Deps, id string) bool {
	p := probeByID(d, id)
	if p.Enabled == nil {
		return true
	}
	return p.Enabled(d)
}

func dialOK(ctx context.Context, d *Deps, host string, port int) bool {
	conn, err := d.Dial(ctx, "tcp", net.JoinHostPort(host, fmt.Sprint(port)))
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// runProbe mirrors the legacy reachability semantics: public services
// must answer on the public IPv4 (and IPv6 when configured); a
// service answering on its backend address but not publicly is
// running-but-unreachable, a different failure than not running.
// Port 53 skips the backend fallback so a downed NSD is never
// masked by unbound answering the same port.
func runProbe(ctx context.Context, d *Deps, p probe, r *Reporter) {
	backend := "127.0.0.1"
	if p.HostVar != "" {
		backend = d.flag(p.HostVar, "127.0.0.1")
	}
	// In Docker, dialing d.PublicIP proves nothing: it is the box's
	// externally-visible address, not one bound to any interface inside
	// the sibling container actually running this service, so it can
	// never be reached this way regardless of whether the service is
	// healthy. Backend (container-name) reachability is the only signal
	// that means anything from inside another container.
	if !p.Public || d.InDocker {
		r.Step(p.Label+" is reachable", func(s *StepCtx) {
			if !dialOK(ctx, d, backend, p.Port) {
				s.Failf("%s is not running (port %d on %s).", p.Label, p.Port, backend)
				hintForProbe(s, p)
			}
		})
		return
	}
	if d.PublicIPv6 == "" {
		r.Step(p.Label+" is reachable", func(s *StepCtx) {
			probePublicIPv4(ctx, d, p, backend, s)
		})
		return
	}
	// With IPv6 configured, an IPv6-only outage gets its own row
	// instead of hiding inside a single reachability step.
	v4up := false
	r.Step(p.Label+" answers on the public IPv4 address", func(s *StepCtx) {
		v4up = probePublicIPv4(ctx, d, p, backend, s)
	})
	r.Step(p.Label+" also answers over IPv6", func(s *StepCtx) {
		if !v4up {
			s.Skipf("no IPv4 answer to compare against")
			return
		}
		if !dialOK(ctx, d, d.PublicIPv6, p.Port) {
			s.Failf("%s is running and available over IPv4 but is not accessible over IPv6 at %s port %d.", p.Label, d.PublicIPv6, p.Port)
		}
	})
}

// probePublicIPv4 reports whether a public service answers on the
// public IPv4 address, distinguishing not-running from
// running-but-not-public via the backend fallback. Port 53 skips the
// fallback so a downed NSD is never masked by unbound.
func probePublicIPv4(ctx context.Context, d *Deps, p probe, backend string, s *StepCtx) bool {
	if dialOK(ctx, d, d.PublicIP, p.Port) {
		return true
	}
	if p.Port != 53 && dialOK(ctx, d, backend, p.Port) {
		s.Failf("%s is running but is not publicly accessible at %s:%d.", p.Label, d.PublicIP, p.Port)
		return false
	}
	s.Failf("%s is not running (port %d).", p.Label, p.Port)
	hintForProbe(s, p)
	return false
}

// serviceHints maps a probe ID to the helper's service name, for
// probes backed by a service the helper is allowed to restart. A
// probe absent here (ssh, rspamd, redis, ...) has no single restart
// target, so it gets no hint rather than a guess.
var serviceHints = map[string]string{
	"lmtp":       "dovecot",
	"nsd":        "nsd",
	"smtp":       "postfix",
	"smtps":      "postfix",
	"submission": "postfix",
	"imaps":      "dovecot",
	"sieve":      "dovecot",
	"http":       "nginx",
	"https":      "nginx",
}

func hintForProbe(s *StepCtx, p probe) {
	if svc, ok := serviceHints[p.ID]; ok {
		s.Hint("service.restart " + svc)
	}
}

func checkMailQueue(ctx context.Context, d *Deps, _ string, r *Reporter) {
	haveCount := false
	count := 0
	r.Step("Mail queue is not backing up", func(s *StepCtx) {
		// postqueue -j prints one JSON object per queued message;
		// counting lines is counting messages.
		out, err := d.PostfixQueue(ctx)
		if err != nil {
			s.Warnf("could not read the mail queue: %v", err)
			return
		}
		for _, line := range strings.Split(out, "\n") {
			if strings.TrimSpace(line) != "" {
				count++
			}
		}
		haveCount = true
		s.Expect("an empty or small queue", fmt.Sprintf("%d queued messages", count))
		switch {
		case count > 500:
			s.Failf("The outbound mail queue holds %d messages - deliveries are failing or the box is emitting bulk mail.", count)
			s.Hint("postqueue -p")
		case count > 100:
			s.Warnf("The outbound mail queue holds %d messages.", count)
			s.Hint("postqueue -p")
		default:
			s.Passf("%d", count)
		}
	})
	r.Step("Mail queue is near its usual size", func(s *StepCtx) {
		if !haveCount || d.Store == nil {
			s.Skipf("no queue reading")
			return
		}
		// Heuristic 2 of 3: the queue is usually near-empty, so a
		// depth of ten times the last day's median (and at least 20)
		// is a spike worth surfacing even while it is still far below
		// the absolute warning threshold.
		samples, err := samplesSince(ctx, d, "mail-queue-depth", d.Now().Add(-24*time.Hour))
		if err != nil {
			s.Skipf("no sample history: %v", err)
			return
		}
		recordSample(ctx, d, "mail-queue-depth", float64(count), 7*24*time.Hour)
		if len(samples) < 12 {
			return // under an hour of history: nothing to deviate from
		}
		values := make([]float64, len(samples))
		for i, smp := range samples {
			values[i] = smp.value
		}
		usual := median(values)
		if float64(count) > 10*usual && count >= 20 {
			s.Expect(fmt.Sprintf("around %.0f queued messages (last day's median)", usual),
				fmt.Sprintf("%d queued messages", count))
			s.Warnf("The outbound mail queue jumped to %d messages (usually around %.0f) - something started sending or deliveries started failing. Inspect with: postqueue -p",
				count, usual)
		}
	})
}
