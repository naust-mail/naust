package checkview

import (
	"testing"
	"time"

	"naust/daemon/internal/store/ent"
)

func TestBuildGroupsCountsAndExitCode(t *testing.T) {
	base := time.Date(2026, 7, 12, 9, 0, 0, 0, time.UTC)
	newest := base.Add(10 * time.Minute)
	rows := []*ent.CheckResult{
		{Check: "free-disk-space", Category: "system", Status: StatusOK, RanAt: base},
		{Check: "quiet-thing", Category: "system", Status: StatusOK, RanAt: base},
		{Check: "retired-thing", Category: "system", Status: StatusOK, RanAt: base}, // not in catalog
		{Check: "service:dovecot", Category: "services", Status: StatusError, Message: "unit failed", RanAt: newest},
		{Check: "mail-tls", Category: "mail", Domain: "a.com", Status: StatusWarning, RanAt: base},
		{Check: "mail-tls", Category: "mail", Domain: "b.com", Status: StatusOK, RanAt: base},
	}
	cat := map[string]Meta{
		"free-disk-space": {Title: "Free disk space", Class: "metric"},
		"quiet-thing":     {Title: "Quiet thing", Class: "quiet"},
		"service:dovecot": {Title: "Dovecot", Class: "standard"},
		"mail-tls":        {Title: "Mail TLS", Class: "standard"},
	}

	snap := build(rows, cat)

	if len(snap.Groups) != 3 {
		t.Fatalf("groups = %d, want 3", len(snap.Groups))
	}
	if snap.Groups[0].Category != "system" || snap.Groups[1].Category != "services" || snap.Groups[2].Category != "mail" {
		t.Fatalf("group order = %s/%s/%s", snap.Groups[0].Category, snap.Groups[1].Category, snap.Groups[2].Category)
	}
	if len(snap.Groups[0].Rows) != 3 {
		t.Fatalf("system rows = %d, want 3", len(snap.Groups[0].Rows))
	}

	// Catalog join carries Title + Class through.
	if r := snap.Groups[0].Rows[0]; r.Title != "Free disk space" || r.Class != "metric" {
		t.Fatalf("disk row = %+v, want titled metric", r)
	}
	// Retired check (absent from catalog) falls back to its key + standard class.
	if r := snap.Groups[0].Rows[2]; r.Title != "retired-thing" || r.Class != "standard" {
		t.Fatalf("retired row = %+v, want key-titled standard", r)
	}

	if snap.OK != 4 || snap.Warning != 1 || snap.Error != 1 || snap.Skipped != 0 {
		t.Fatalf("counts ok/warn/err/skip = %d/%d/%d/%d, want 4/1/1/0", snap.OK, snap.Warning, snap.Error, snap.Skipped)
	}
	if snap.ExitCode() != 2 {
		t.Fatalf("exit code = %d, want 2 (has error)", snap.ExitCode())
	}
	if !snap.LastRun.Equal(newest) {
		t.Fatalf("last run = %v, want %v", snap.LastRun, newest)
	}
}

func TestExitCodeWarningVsClean(t *testing.T) {
	warn := build([]*ent.CheckResult{{Check: "x", Category: "c", Status: StatusWarning}}, map[string]Meta{})
	if warn.ExitCode() != 1 {
		t.Fatalf("warnings-only exit = %d, want 1", warn.ExitCode())
	}
	clean := build([]*ent.CheckResult{{Check: "x", Category: "c", Status: StatusOK}}, map[string]Meta{})
	if clean.ExitCode() != 0 {
		t.Fatalf("all-ok exit = %d, want 0", clean.ExitCode())
	}
}

func TestDecodeSteps(t *testing.T) {
	if s := decodeSteps(""); s != nil {
		t.Fatalf("empty blob = %v, want nil", s)
	}
	if s := decodeSteps("not json"); s != nil {
		t.Fatalf("bad blob = %v, want nil", s)
	}
	if s := decodeSteps(`[{"label":"unit","expected":"active","observed":"failed"}]`); len(s) != 1 {
		t.Fatalf("valid blob decoded to %d steps, want 1", len(s))
	}
}
