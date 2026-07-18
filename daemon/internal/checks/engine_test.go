package checks

import (
	"context"
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"testing"
	"time"

	"naust/daemon/internal/store"
	"naust/daemon/internal/store/ent"
	entcheckresult "naust/daemon/internal/store/ent/checkresult"
	entsetting "naust/daemon/internal/store/ent/setting"
)

var testNow = time.Date(2026, 7, 8, 12, 0, 0, 0, time.UTC)

func testStore(t *testing.T) *ent.Client {
	t.Helper()
	client, err := store.Open(store.EngineSQLite, filepath.Join(t.TempDir(), "test.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() })
	if err := client.Schema.Create(context.Background()); err != nil {
		t.Fatal(err)
	}
	return client
}

func testEngine(t *testing.T, checks []Check) *Engine {
	t.Helper()
	e := &Engine{
		Deps: Deps{
			Store: testStore(t),
			Now:   func() time.Time { return testNow },
			Log:   log.New(os.Stderr, "", 0),
		},
		Checks: checks,
	}
	e.fillDefaults()
	return e
}

func row(t *testing.T, e *Engine, check, domain string) *ent.CheckResult {
	t.Helper()
	r, err := e.Deps.Store.CheckResult.Query().
		Where(entcheckresult.CheckEQ(check), entcheckresult.DomainEQ(domain)).
		Only(context.Background())
	if err != nil {
		t.Fatalf("row %s/%s: %v", check, domain, err)
	}
	return r
}

func okCheck(name string) Check {
	return Check{Name: name, Category: "test", Tier: TierFast,
		Run: func(ctx context.Context, d *Deps, _ string, r *Reporter) {
			r.Step("fine", func(s *StepCtx) {})
		}}
}

func TestRunPersistsAndTracksFirstFailure(t *testing.T) {
	failing := true
	chk := Check{Name: "flaky", Category: "test", Tier: TierFast,
		Run: func(ctx context.Context, d *Deps, _ string, r *Reporter) {
			r.Step("probe", func(s *StepCtx) {
				if failing {
					s.Failf("down")
					s.Hint("service.restart thing")
					s.Expect("up", "down")
				}
			})
		}}
	e := testEngine(t, []Check{chk})
	ctx := context.Background()

	e.runBatch(ctx, e.Checks, "", true)
	got := row(t, e, "flaky", "")
	if got.Status != "error" || got.Message != "down" {
		t.Fatalf("row = %s %q", got.Status, got.Message)
	}
	if got.FirstFailedAt == nil || !got.FirstFailedAt.Equal(testNow) {
		t.Errorf("first_failed_at = %v", got.FirstFailedAt)
	}
	var steps []Step
	if err := json.Unmarshal([]byte(got.Steps), &steps); err != nil || len(steps) != 1 {
		t.Fatalf("steps = %s (%v)", got.Steps, err)
	}
	if steps[0].FixHint != "service.restart thing" || steps[0].Expected != "up" {
		t.Errorf("step = %+v", steps[0])
	}

	// Still failing later: onset time is preserved.
	later := testNow.Add(time.Hour)
	e.Deps.Now = func() time.Time { return later }
	e.runBatch(ctx, e.Checks, "", true)
	if got = row(t, e, "flaky", ""); got.FirstFailedAt == nil || !got.FirstFailedAt.Equal(testNow) {
		t.Errorf("first_failed_at moved: %v", got.FirstFailedAt)
	}

	// Recovery clears it.
	failing = false
	e.runBatch(ctx, e.Checks, "", true)
	if got = row(t, e, "flaky", ""); got.Status != "ok" || got.FirstFailedAt != nil {
		t.Errorf("after recovery: %s first_failed_at=%v", got.Status, got.FirstFailedAt)
	}
}

func TestDependencyGate(t *testing.T) {
	depFails := true
	dep := Check{Name: "resolver", Category: "test", Tier: TierFast,
		Run: func(ctx context.Context, d *Deps, _ string, r *Reporter) {
			r.Step("up", func(s *StepCtx) {
				if depFails {
					s.Failf("resolver down")
				}
			})
		}}
	ran := 0
	dependent := Check{Name: "lookup", Category: "test", Tier: TierFast, DependsOn: []string{"resolver"},
		Run: func(ctx context.Context, d *Deps, _ string, r *Reporter) {
			ran++
			r.Step("query", func(s *StepCtx) {})
		}}
	e := testEngine(t, []Check{dependent, dep}) // dependent listed first on purpose
	ctx := context.Background()

	e.runBatch(ctx, e.Checks, "", true)
	if ran != 0 {
		t.Fatalf("dependent ran despite failed dependency")
	}
	got := row(t, e, "lookup", "")
	if got.Status != "skipped" || got.Message != `skipped: "resolver" failed` {
		t.Errorf("row = %s %q", got.Status, got.Message)
	}

	depFails = false
	e.runBatch(ctx, e.Checks, "", true)
	if ran != 1 {
		t.Fatalf("dependent did not run after dependency recovered")
	}

	// Dependency NOT in the batch: gate on the stored result.
	depFails = true
	e.runBatch(ctx, []Check{dep}, "", true)
	e.runBatch(ctx, []Check{dependent}, "", true)
	if ran != 1 {
		t.Errorf("dependent ran against stored failed dependency")
	}
}

func TestPerDomainFanoutAndPrune(t *testing.T) {
	domains := []string{"a.example", "b.example"}
	chk := Check{Name: "per-domain", Category: "test", Tier: TierHourly,
		Domains: func(ctx context.Context, d *Deps) ([]string, error) { return domains, nil },
		Run: func(ctx context.Context, d *Deps, domain string, r *Reporter) {
			r.Step("visit "+domain, func(s *StepCtx) {})
		}}
	e := testEngine(t, []Check{chk})
	ctx := context.Background()

	e.runBatch(ctx, e.Checks, "", true)
	row(t, e, "per-domain", "a.example")
	row(t, e, "per-domain", "b.example")

	// Domain filter: only the matching instance runs, nothing pruned.
	domains = []string{"a.example", "b.example"}
	e.runBatch(ctx, e.Checks, "b.example", false)
	row(t, e, "per-domain", "a.example")

	// b vanishes; a full run prunes its row.
	domains = []string{"a.example"}
	e.runBatch(ctx, e.Checks, "", true)
	n, err := e.Deps.Store.CheckResult.Query().
		Where(entcheckresult.CheckEQ("per-domain")).Count(ctx)
	if err != nil || n != 1 {
		t.Errorf("rows after prune = %d (%v)", n, err)
	}
}

func TestConfigCadenceAndDisable(t *testing.T) {
	e := testEngine(t, []Check{okCheck("tunable")})
	ctx := context.Background()

	// Fresh store: due.
	if err := e.runDue(ctx, false); err != nil {
		t.Fatal(err)
	}
	first := row(t, e, "tunable", "").RanAt

	// Recently run: not due at fast cadence.
	e.Deps.Now = func() time.Time { return testNow.Add(2 * time.Minute) }
	if err := e.runDue(ctx, false); err != nil {
		t.Fatal(err)
	}
	if got := row(t, e, "tunable", ""); !got.RanAt.Equal(first) {
		t.Fatalf("ran again before cadence elapsed")
	}

	// Admin override to weekly: still not due after 6 days.
	setConfig(t, e, `{"checks":{"tunable":{"cadence":"weekly"}}}`)
	e.Deps.Now = func() time.Time { return testNow.Add(6 * 24 * time.Hour) }
	if err := e.runDue(ctx, false); err != nil {
		t.Fatal(err)
	}
	if got := row(t, e, "tunable", ""); !got.RanAt.Equal(first) {
		t.Fatalf("weekly override not honored")
	}
	e.Deps.Now = func() time.Time { return testNow.Add(8 * 24 * time.Hour) }
	if err := e.runDue(ctx, false); err != nil {
		t.Fatal(err)
	}
	if got := row(t, e, "tunable", ""); got.RanAt.Equal(first) {
		t.Fatalf("did not run after weekly cadence elapsed")
	}

	// Disabled: result replaced by the disabled marker.
	setConfig(t, e, `{"checks":{"tunable":{"enabled":false}}}`)
	if err := e.runDue(ctx, false); err != nil {
		t.Fatal(err)
	}
	if got := row(t, e, "tunable", ""); got.Status != "skipped" || got.Message != "disabled by configuration" {
		t.Errorf("disabled row = %s %q", got.Status, got.Message)
	}

	// A manual run overrides the disable.
	e.runManual(ctx, RunRequest{Checks: []string{"tunable"}})
	if got := row(t, e, "tunable", ""); got.Status != "ok" {
		t.Errorf("manual run of disabled check = %s", got.Status)
	}
}

func setConfig(t *testing.T, e *Engine, value string) {
	t.Helper()
	err := e.Deps.Store.Setting.Create().
		SetKey(SettingKey).SetValue(value).
		OnConflictColumns(entsetting.FieldKey).UpdateNewValues().
		Exec(context.Background())
	if err != nil {
		t.Fatal(err)
	}
}

func TestNotApplicableAndPanicRecovery(t *testing.T) {
	na := Check{Name: "wrong-variant", Category: "test", Tier: TierFast,
		Enabled: func(d *Deps) bool { return false },
		Run:     func(ctx context.Context, d *Deps, _ string, r *Reporter) { t.Fatal("must not run") }}
	buggy := Check{Name: "buggy", Category: "test", Tier: TierFast,
		Run: func(ctx context.Context, d *Deps, _ string, r *Reporter) {
			r.Step("explode", func(s *StepCtx) { panic("boom") })
		}}
	e := testEngine(t, []Check{na, buggy})
	e.runBatch(context.Background(), e.Checks, "", true)

	if got := row(t, e, "wrong-variant", ""); got.Status != "skipped" || got.Message != "not applicable" {
		t.Errorf("not-applicable row = %s %q", got.Status, got.Message)
	}
	if got := row(t, e, "buggy", ""); got.Status != "error" || got.Message != "check bug: boom" {
		t.Errorf("panic row = %s %q", got.Status, got.Message)
	}
}

func TestValidateConfig(t *testing.T) {
	if err := (Config{Checks: map[string]CheckOverride{"x": {Cadence: "sometimes"}}}).Validate(); err == nil {
		t.Error("bad cadence accepted")
	}
	if err := (Config{Report: "hourly"}).Validate(); err == nil {
		t.Error("bad report schedule accepted")
	}
	if err := (Config{Checks: map[string]CheckOverride{"x": {Cadence: "weekly"}}, Report: "daily"}).Validate(); err != nil {
		t.Errorf("valid config rejected: %v", err)
	}
}

func TestAllChecksAreWellFormed(t *testing.T) {
	names := map[string]bool{}
	for _, chk := range All() {
		if chk.Name == "" || chk.Category == "" || chk.Run == nil || chk.Tier == "" {
			t.Errorf("check %+v is missing required fields", chk.Name)
		}
		if names[chk.Name] {
			t.Errorf("duplicate check name %q", chk.Name)
		}
		names[chk.Name] = true
		if _, ok := cadenceIntervals[string(chk.Tier)]; !ok {
			t.Errorf("check %q has unknown tier %q", chk.Name, chk.Tier)
		}
		for _, dep := range chk.DependsOn {
			if !names[dep] && dep != "unbound" {
				t.Errorf("check %q depends on unknown %q", chk.Name, dep)
			}
		}
	}
}

// Regression for the system-alias retirement: results of checks that
// no longer exist must not haunt the panel as frozen rows - Start
// prunes them. (The retired system-alias check kept showing "failing
// since ..." forever after its replacement landed.)
func TestPruneStaleRemovesRetiredCheckResults(t *testing.T) {
	e := testEngine(t, []Check{okCheck("alive")})
	ctx := context.Background()
	e.runBatch(ctx, e.Checks, "", true)

	e.Deps.Store.CheckResult.Create().
		SetCheck("system-alias").SetCategory("system").SetDomain("").
		SetStatus("error").SetMessage("retired").SetRanAt(testNow).
		SaveX(ctx)

	e.pruneStale(ctx)
	if n, err := e.Deps.Store.CheckResult.Query().
		Where(entcheckresult.CheckEQ("system-alias")).Count(ctx); err != nil || n != 0 {
		t.Errorf("retired rows after prune = %d (%v)", n, err)
	}
	row(t, e, "alive", "")
}
