package main

import (
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"naust/daemon/internal/api"
	"naust/daemon/internal/checkview"
)

func mkStep(name, expected, observed, message string) api.CheckStep {
	return api.CheckStep{Name: name, Expected: expected, Observed: observed, Message: message}
}

// worstStatus on an empty category is OK (nothing is wrong), not "" or a panic -
// an empty roster must render as a calm category, never a phantom failure.
func TestWorstStatusEmpty(t *testing.T) {
	if got := worstStatus(nil); got != checkview.StatusOK {
		t.Errorf("worstStatus(nil) = %q, want %q", got, checkview.StatusOK)
	}
}

// An unrecognized status word sorts into the ok tier, so a garbled row can never
// masquerade as an error at the top of a category or crash the sort comparator.
func TestStatusTierUnknown(t *testing.T) {
	if got := statusTier("mystery"); got != 2 {
		t.Errorf("statusTier(unknown) = %d, want 2 (ok tier)", got)
	}
}

// groupByCheck only merges ADJACENT rows of the same check. managerd stores a
// check's rows contiguously; this pins that assumption so interleaved names stay
// separate groups rather than silently coalescing across the whole category.
func TestGroupByCheckInterleaved(t *testing.T) {
	rows := []checkview.Row{{Name: "a"}, {Name: "b"}, {Name: "a"}}
	if groups := groupByCheck(rows); len(groups) != 3 {
		t.Fatalf("interleaved names coalesced: got %d groups, want 3", len(groups))
	}
}

// metricBadges must ignore non-metric rows, drop a metric with no value, and show
// a repeated metric name only once - a collapsed line should never carry a blank
// badge or the same number twice.
func TestMetricBadgesOffHappyPath(t *testing.T) {
	rows := []checkview.Row{
		{Name: "disk", Class: "metric", Title: "Free disk space", ShortLabel: "disk", Message: "12%"},
		{Name: "disk", Class: "metric", Title: "Free disk space", ShortLabel: "disk", Message: "12%"}, // dup name
		{Name: "queue", Class: "metric", Title: "Mail queue", ShortLabel: "queue", Message: ""},       // no value
		{Name: "unit", Class: "standard", Title: "Dovecot", Message: "active"},                        // not a metric
	}
	out := metricBadges(rows)
	if n := strings.Count(out, "disk 12%"); n != 1 {
		t.Errorf("duplicate metric name rendered %d times, want 1: %q", n, out)
	}
	if strings.Contains(out, "queue") {
		t.Errorf("value-less metric should be dropped: %q", out)
	}
	if strings.Contains(out, "Dovecot") || strings.Contains(out, "active") {
		t.Errorf("non-metric row leaked into badges: %q", out)
	}
}

// metricLabel falls back to a shortened title only when a row carries no catalog
// ShortLabel (a metric with no matching check definition); ShortLabel wins when set.
func TestMetricLabelFallback(t *testing.T) {
	if got := metricLabel(checkview.Row{Title: "Free disk space"}); got != "disk space" {
		t.Errorf("fallback label = %q, want %q", got, "disk space")
	}
	if got := metricLabel(checkview.Row{Title: "Free disk space", ShortLabel: "disk"}); got != "disk" {
		t.Errorf("ShortLabel should win, got %q", got)
	}
}

// fill must never hand strings.Repeat a negative count: when the content already
// exceeds the width it clamps the gap to one space instead of panicking, and it
// keeps both sides intact.
func TestFillOverflowDoesNotPanic(t *testing.T) {
	out := fill("a-very-long-left-label", "and-a-long-right-value", 4)
	if !strings.Contains(out, "a-very-long-left-label") || !strings.Contains(out, "and-a-long-right-value") {
		t.Errorf("overflow fill dropped content: %q", out)
	}
}

// ago buckets by magnitude; check each boundary lands in the right unit.
func TestAgoBuckets(t *testing.T) {
	now := time.Now()
	cases := []struct {
		d    time.Duration
		want string
	}{
		{30 * time.Second, "just now"},
		{5 * time.Minute, "5m"},
		{3 * time.Hour, "3h"},
		{50 * time.Hour, "2d"},
	}
	for _, c := range cases {
		if got := ago(now.Add(-c.d)); got != c.want {
			t.Errorf("ago(-%v) = %q, want %q", c.d, got, c.want)
		}
	}
}

// stepText renders the expected/observed form, the plain-message form, and the
// bare-name form depending on which fields a step carries.
func TestStepTextForms(t *testing.T) {
	if got := stepText(mkStep("unit", "active", "failed", "")); !strings.Contains(got, "expected: active") || !strings.Contains(got, "observed: failed") {
		t.Errorf("expected/observed form wrong: %q", got)
	}
	if got := stepText(mkStep("queue", "", "", "12 held")); got != "queue  12 held" {
		t.Errorf("message form = %q, want %q", got, "queue  12 held")
	}
	if got := stepText(mkStep("bare", "", "", "")); got != "bare" {
		t.Errorf("bare-name form = %q, want %q", got, "bare")
	}
}

// rowMessage falls back to the status word when a row has no message, so a row
// never renders a blank value column.
func TestRowMessageFallback(t *testing.T) {
	if got := rowMessage(checkview.Row{Status: checkview.StatusOK}); got != checkview.StatusOK {
		t.Errorf("empty-message row = %q, want status fallback %q", got, checkview.StatusOK)
	}
	if got := rowMessage(checkview.Row{Status: checkview.StatusOK, Message: "healthy"}); got != "healthy" {
		t.Errorf("message should win, got %q", got)
	}
}

// Cursor navigation clamps at both ends and enter toggles the selected category.
func TestDoctorNavigationClamps(t *testing.T) {
	host, probes, snap := demoData("healthy")
	m := newDoctorModel(host, probes, snap)

	// Up at the top stays at 0.
	up, _ := m.Update(tea.KeyMsg{Type: tea.KeyUp})
	if c := up.(doctorModel).cursor; c != 0 {
		t.Errorf("cursor moved above 0 to %d", c)
	}

	// Down past the end clamps at the last category.
	cur := m
	for i := 0; i < len(m.cats)+3; i++ {
		next, _ := cur.Update(tea.KeyMsg{Type: tea.KeyDown})
		cur = next.(doctorModel)
	}
	if want := len(m.cats) - 1; cur.cursor != want {
		t.Errorf("cursor = %d, want clamp at %d", cur.cursor, want)
	}

	// Enter toggles the selected category's expansion (and toggles back).
	sel := "cat:" + m.cats[0].Category
	on, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if !on.(doctorModel).expanded[sel] {
		t.Errorf("enter did not expand %q", sel)
	}
	off, _ := on.(doctorModel).Update(tea.KeyMsg{Type: tea.KeyEnter})
	if off.(doctorModel).expanded[sel] {
		t.Errorf("second enter did not collapse %q", sel)
	}
}
