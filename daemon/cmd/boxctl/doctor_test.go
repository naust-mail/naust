package main

import (
	"strings"
	"testing"
)

func render(t *testing.T, state string) string {
	t.Helper()
	host, probes, snap := demoData(state)
	return newDoctorModel(host, probes, snap).View()
}

// At rest every category is a collapsed one-liner: chevron, glyph, name, and a
// count + inline metric badges. Daemon is just another category, first in the
// fixed order. Per-check rows stay folded until expanded.
func TestDoctorHealthyDashboard(t *testing.T) {
	out := render(t, "healthy")
	for _, want := range []string{
		"boxctl doctor",
		"DAEMON", "5 checks ok",
		"SYSTEM", "6 checks ok", "disk 12%", "memory 38%",
		"SERVICES", "3 checks ok", "queue 0",
		"MAIL", "2 checks ok", "backup 4h ago",
		"All checks passing.",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("healthy dashboard missing %q\n---\n%s", want, out)
		}
	}
	// Per-check rows are folded, not shown at rest.
	if strings.Contains(out, "Free disk space") {
		t.Errorf("healthy dashboard should fold per-check rows away:\n%s", out)
	}
}

// A failing category shows its own red tally on the collapsed line ("1 failing");
// nothing auto-expands.
func TestDoctorFailuresCollapsed(t *testing.T) {
	out := render(t, "failures")
	for _, want := range []string{
		"SERVICES", "1 failing",
		"MAIL", "1 warning",
		"1 error, 1 warning.",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("failures view missing %q\n---\n%s", want, out)
		}
	}
	// Detail stays folded until the user expands.
	if strings.Contains(out, "expected: active") {
		t.Errorf("failing check detail should stay folded until expanded:\n%s", out)
	}
}

// Expanding a failing category reveals the check, its expected/observed step, and
// the fix hint. Checks are ordered errors first.
func TestDoctorFailuresExpanded(t *testing.T) {
	host, probes, snap := demoData("failures")
	m := newDoctorModel(host, probes, snap)
	// services is the second category (after daemon); expand it.
	m.expanded["cat:services"] = true
	out := m.View()
	for _, want := range []string{
		"Dovecot", "expected: active", "observed: failed",
		"fix: sudo systemctl restart dovecot",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expanded services missing %q\n---\n%s", want, out)
		}
	}
}

// Daemon down = the DAEMON category goes red with a failing tally and a stale
// banner; expanding it shows the probe's expected/observed and the restart fix.
func TestDoctorDaemonDown(t *testing.T) {
	host, probes, snap := demoData("down")
	m := newDoctorModel(host, probes, snap)
	out := m.View()
	for _, want := range []string{
		"DAEMON", "failing",
		"last successful run",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("daemon-down view missing %q\n---\n%s", want, out)
		}
	}
	m.expanded["cat:daemon"] = true
	exp := m.View()
	for _, want := range []string{
		"systemd unit naust-managerd", "failed",
		"fix: sudo systemctl restart naust-managerd",
	} {
		if !strings.Contains(exp, want) {
			t.Errorf("expanded daemon-down missing %q\n---\n%s", want, exp)
		}
	}
	// An atomic probe must not repeat itself as an expected/observed child.
	if strings.Contains(exp, "observed: failed") {
		t.Errorf("daemon probe should not restate itself as a step:\n%s", exp)
	}
}

// Daemon is the first category and does not reorder by status.
func TestDaemonIsFirstCategory(t *testing.T) {
	host, probes, snap := demoData("healthy")
	m := newDoctorModel(host, probes, snap)
	if len(m.cats) != 4 {
		t.Fatalf("expected 4 categories (daemon + 3), got %d", len(m.cats))
	}
	if m.cats[0].Category != "daemon" {
		t.Fatalf("daemon should be the first category, got %q", m.cats[0].Category)
	}
}

// Within a category, checks are ordered errors first, then warnings, then ok,
// alphabetical within each tier.
func TestChecksSortedByStatusWithinCategory(t *testing.T) {
	// A category with mixed statuses in non-status order.
	groups := sortedCheckGroups(demoMixedCategory().Rows)
	var order []string
	for _, grp := range groups {
		order = append(order, grp[0].Status)
	}
	// errors (tier 0) must precede warnings (1) must precede ok (2).
	for i := 1; i < len(order); i++ {
		if statusTier(order[i]) < statusTier(order[i-1]) {
			t.Fatalf("checks not status-ordered: %v", order)
		}
	}
}
