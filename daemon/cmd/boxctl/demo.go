package main

import (
	"time"

	"naust/daemon/internal/api"
	"naust/daemon/internal/checkview"
	"naust/daemon/internal/liveness"
)

// demoData returns fake but realistic doctor input for `--demo`, so the TUI can
// be tested end to end without a real box. States: "healthy", "failures", "down".
func demoData(state string) (string, []liveness.Result, checkview.Snapshot) {
	host := "naust.example.com"
	up := []liveness.Result{
		{Name: "managerd binary", OK: true, Detail: "present", Expected: "present"},
		{Name: "systemd unit naust-managerd", OK: true, Detail: "active", Expected: "active"},
		{Name: "API 127.0.0.1:10223", OK: true, Detail: "listening", Expected: "listening"},
		{Name: "control DB", OK: true, Detail: "readable", Expected: "readable"},
		{Name: "helper socket", OK: true, Detail: "reachable", Expected: "reachable"},
	}
	switch state {
	case "failures":
		return host, up, finalize(rosterFailures())
	case "down":
		down := []liveness.Result{
			{Name: "managerd binary", OK: true, Detail: "present", Expected: "present"},
			{Name: "systemd unit naust-managerd", OK: false, Detail: "failed", Expected: "active"},
			{Name: "API 127.0.0.1:10223", OK: false, Detail: "not listening", Expected: "listening"},
			{Name: "control DB", OK: true, Detail: "readable", Expected: "readable"},
			{Name: "helper socket", OK: false, Detail: "unreachable", Expected: "reachable"},
		}
		return host, down, finalize(rosterHealthy())
	default:
		return host, up, finalize(rosterHealthy())
	}
}

func row(cat, name, title, class, domain, status, msg string) checkview.Row {
	return checkview.Row{Name: name, Title: title, Category: cat, Class: class, Domain: domain, Status: status, Message: msg, RanAt: time.Now()}
}

// metricRow is row() for a metric-class check, carrying the ShortLabel the
// collapsed badge renders ("disk 12%").
func metricRow(cat, name, title, short, domain, status, msg string) checkview.Row {
	r := row(cat, name, title, "metric", domain, status, msg)
	r.ShortLabel = short
	return r
}

func rosterHealthy() []checkview.Group {
	return []checkview.Group{
		{Category: "system", Rows: []checkview.Row{
			metricRow("system", "free-disk-space", "Free disk space", "disk", "", "ok", "12%"),
			metricRow("system", "free-memory", "Free memory", "memory", "", "ok", "38%"),
			row("system", "software-updates", "Software updates", "standard", "", "ok", "up to date"),
			row("system", "ufw", "UFW firewall", "standard", "", "ok", "active"),
			row("system", "disk-health", "Disk health", "quiet", "", "ok", ""),
			row("system", "system-mail-routing", "System mail routing", "quiet", "", "ok", ""),
		}},
		{Category: "services", Rows: []checkview.Row{
			row("services", "service:postfix", "Postfix", "standard", "", "ok", "running"),
			row("services", "service:dovecot", "Dovecot", "standard", "", "ok", "running"),
			metricRow("services", "mail-queue", "Mail queue", "queue", "", "ok", "0"),
		}},
		{Category: "mail", Rows: []checkview.Row{
			row("mail", "mail-tls", "Mail TLS", "standard", "a.example.com", "ok", "ok"),
			row("mail", "mail-tls", "Mail TLS", "standard", "b.example.com", "ok", "ok"),
			row("mail", "mail-tls", "Mail TLS", "standard", "c.example.com", "ok", "ok"),
			metricRow("mail", "backup", "Backup", "backup", "", "ok", "4h ago"),
		}},
	}
}

func rosterFailures() []checkview.Group {
	g := rosterHealthy()
	// Dovecot down, with steps + a fix hint.
	g[1].Rows[1] = checkview.Row{
		Name: "service:dovecot", Title: "Dovecot", Category: "services", Class: "standard",
		Status: "error", Message: "unit failed", RanAt: time.Now(),
		Steps: []api.CheckStep{
			{Name: "systemd unit active", Status: "error", Expected: "active", Observed: "failed"},
			{Name: "port 993 (IMAPS)", Status: "error", Expected: "open", Observed: "closed", FixHint: "sudo systemctl restart dovecot"},
		},
	}
	// One of three mail-TLS domains warning.
	g[2].Rows[1] = row("mail", "mail-tls", "Mail TLS", "standard", "b.example.com", "warning", "cert expires in 9 days")
	return g
}

// demoMixedCategory is a category whose checks are deliberately out of status
// order, for exercising the errors-first within-category sort.
func demoMixedCategory() checkview.Group {
	return checkview.Group{Category: "system", Rows: []checkview.Row{
		row("system", "aaa-ok", "Aaa ok", "standard", "", "ok", "fine"),
		row("system", "zzz-error", "Zzz error", "standard", "", "error", "broken"),
		row("system", "mmm-warn", "Mmm warn", "standard", "", "warning", "iffy"),
	}}
}

// finalize recomputes the snapshot counts and last-run from its rows.
func finalize(groups []checkview.Group) checkview.Snapshot {
	snap := checkview.Snapshot{Groups: groups}
	for _, gr := range groups {
		for _, r := range gr.Rows {
			if r.RanAt.After(snap.LastRun) {
				snap.LastRun = r.RanAt
			}
			switch r.Status {
			case checkview.StatusOK:
				snap.OK++
			case checkview.StatusWarning:
				snap.Warning++
			case checkview.StatusError:
				snap.Error++
			case checkview.StatusSkipped:
				snap.Skipped++
			}
		}
	}
	return snap
}
