package backup

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"entgo.io/ent/dialect/sql"

	"naust/daemon/internal/store"
	"naust/daemon/internal/store/ent"
	entbackuprun "naust/daemon/internal/store/ent/backuprun"
	entlease "naust/daemon/internal/store/ent/lease"
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

// fakeTool scripts each phase.
type fakeTool struct {
	calls      []string
	prepareErr error
	backupErr  error
	pruneErr   error
	checkErr   error
	snapsErr   error
	stats      RunStats
	snaps      []Snapshot
}

func (f *fakeTool) Name() string { return "fake" }
func (f *fakeTool) Prepare(context.Context) error {
	f.calls = append(f.calls, "prepare")
	return f.prepareErr
}
func (f *fakeTool) Backup(context.Context) (RunStats, error) {
	f.calls = append(f.calls, "backup")
	return f.stats, f.backupErr
}
func (f *fakeTool) Prune(context.Context) error {
	f.calls = append(f.calls, "prune")
	return f.pruneErr
}
func (f *fakeTool) Check(context.Context) error {
	f.calls = append(f.calls, "check")
	return f.checkErr
}
func (f *fakeTool) Snapshots(context.Context) ([]Snapshot, error) {
	f.calls = append(f.calls, "snapshots")
	return f.snaps, f.snapsErr
}
func (f *fakeTool) Restore(context.Context, string, string) error {
	f.calls = append(f.calls, "restore")
	return nil
}

func testEngine(t *testing.T, tool *fakeTool) (*Engine, *fakeRun) {
	t.Helper()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "backup"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "backup", "secret_key.txt"), []byte("sekrit\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	fr := &fakeRun{}
	e := &Engine{
		Store:       testStore(t),
		StorageRoot: root,
		Hostname:    "box.example.com",
		Runner:      fr.run,
		NewTool: func(env ToolEnv, name string) (Tool, error) {
			if env.Passphrase != "sekrit" {
				t.Errorf("passphrase = %q", env.Passphrase)
			}
			return tool, nil
		},
		Now: func() time.Time { return testNow },
		Log: log.New(os.Stderr, "", 0),
	}
	e.fillDefaults()
	return e, fr
}

func saveConfig(t *testing.T, e *Engine, cfg Config) {
	t.Helper()
	encoded, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	err = e.Store.Setting.Create().
		SetKey(SettingKey).SetValue(string(encoded)).
		OnConflictColumns(entsetting.FieldKey).UpdateNewValues().
		Exec(context.Background())
	if err != nil {
		t.Fatal(err)
	}
}

func lastRun(t *testing.T, e *Engine) *ent.BackupRun {
	t.Helper()
	row, err := e.Store.BackupRun.Query().
		Order(entbackuprun.ByStartedAt(sql.OrderDesc())).
		First(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return row
}

func TestRunOnceHappyPath(t *testing.T) {
	tool := &fakeTool{
		stats: RunStats{SnapshotID: "abc123", Size: 4096, FileCount: 7},
		snaps: []Snapshot{{ID: "abc123", Time: testNow, Full: true}},
	}
	e, _ := testEngine(t, tool)
	e.runOnce(context.Background(), false)

	if got := strings.Join(tool.calls, ","); got != "prepare,backup,prune,check,snapshots" {
		t.Errorf("calls = %s", got)
	}
	row := lastRun(t, e)
	if row.Status != "ok" || row.Error != "" || row.Warning != "" || row.FinishedAt == nil {
		t.Errorf("run = %+v", row)
	}
	if !strings.Contains(row.Stats, `"snapshot_id":"abc123"`) {
		t.Errorf("stats = %s", row.Stats)
	}
	cache, err := e.Store.Setting.Query().
		Where(entsetting.Key(SnapshotsSettingKey)).Only(context.Background())
	if err != nil || !strings.Contains(cache.Value, `"abc123"`) {
		t.Errorf("snapshot cache = %+v (%v)", cache, err)
	}
}

func TestRunOnceFailuresAndWarnings(t *testing.T) {
	// Backup failure: error run, nothing after backup executes.
	tool := &fakeTool{backupErr: errors.New("target unreachable")}
	e, _ := testEngine(t, tool)
	e.runOnce(context.Background(), false)
	row := lastRun(t, e)
	if row.Status != "error" || !strings.Contains(row.Error, "target unreachable") {
		t.Errorf("run = %+v", row)
	}
	if strings.Contains(strings.Join(tool.calls, ","), "prune") {
		t.Errorf("prune ran after failed backup: %v", tool.calls)
	}

	// Prune and check failures: run stays ok, warnings recorded.
	tool = &fakeTool{pruneErr: errors.New("stale lock"), checkErr: errors.New("pack damaged")}
	e, _ = testEngine(t, tool)
	e.runOnce(context.Background(), false)
	row = lastRun(t, e)
	if row.Status != "ok" {
		t.Errorf("run = %+v", row)
	}
	for _, want := range []string{"stale lock", "pack damaged"} {
		if !strings.Contains(row.Warning, want) {
			t.Errorf("warning %q missing %q", row.Warning, want)
		}
	}

	// check_after_backup=false skips the check.
	tool = &fakeTool{}
	e, _ = testEngine(t, tool)
	cfg := DefaultConfig()
	cfg.CheckAfterBackup = false
	saveConfig(t, e, cfg)
	e.runOnce(context.Background(), false)
	if strings.Contains(strings.Join(tool.calls, ","), "check") {
		t.Errorf("check ran despite config: %v", tool.calls)
	}

	// Disabled: no run row at all.
	tool = &fakeTool{}
	e, _ = testEngine(t, tool)
	saveConfig(t, e, Config{Target: Target{Type: "off"}, KeepWithinDays: 3})
	e.runOnce(context.Background(), true)
	if n, _ := e.Store.BackupRun.Query().Count(context.Background()); n != 0 {
		t.Errorf("disabled run recorded %d rows", n)
	}
	if len(tool.calls) != 0 {
		t.Errorf("tool touched while disabled: %v", tool.calls)
	}

	// Missing key: error run before the tool is touched.
	tool = &fakeTool{}
	e, _ = testEngine(t, tool)
	os.Remove(filepath.Join(e.StorageRoot, "backup", "secret_key.txt"))
	e.runOnce(context.Background(), false)
	row = lastRun(t, e)
	if row.Status != "error" || !strings.Contains(row.Error, "encryption key") {
		t.Errorf("run = %+v", row)
	}
}

// TestRunOnceSkipsWhenLeaseHeldByAnotherProcess proves the lease
// actually gates concurrent runs: a live lease held by a different
// process must stop this replica before it ever touches the tool or
// records a run, which is what prevents two replicas from hitting the
// same restic/duplicity repository together.
func TestRunOnceSkipsWhenLeaseHeldByAnotherProcess(t *testing.T) {
	tool := &fakeTool{}
	e, _ := testEngine(t, tool)
	ctx := context.Background()

	// AcquireLease/ReleaseLease stamp real wall-clock time regardless of
	// e.Now, so the claim must be relative to time.Now(), not testNow.
	if err := e.Store.Lease.Create().
		SetName(leaseName).
		SetHolder("otherhost:9999").
		SetExpiresAt(time.Now().Add(time.Hour)).
		Exec(ctx); err != nil {
		t.Fatal(err)
	}

	e.runOnce(ctx, false)

	if len(tool.calls) != 0 {
		t.Errorf("tool touched despite lease held elsewhere: %v", tool.calls)
	}
	if n, _ := e.Store.BackupRun.Query().Count(ctx); n != 0 {
		t.Errorf("run recorded despite lease held elsewhere: %d rows", n)
	}
}

// TestRunOnceRunsWhenLeaseExpired proves a crashed holder's lapsed
// lease does not permanently wedge backups: an expired claim from
// another host must not block a new run.
func TestRunOnceRunsWhenLeaseExpired(t *testing.T) {
	tool := &fakeTool{stats: RunStats{SnapshotID: "abc"}}
	e, _ := testEngine(t, tool)
	ctx := context.Background()

	if err := e.Store.Lease.Create().
		SetName(leaseName).
		SetHolder("otherhost:9999").
		SetExpiresAt(time.Now().Add(-time.Minute)). // already lapsed
		Exec(ctx); err != nil {
		t.Fatal(err)
	}

	e.runOnce(ctx, false)

	row := lastRun(t, e)
	if row.Status != "ok" {
		t.Errorf("run = %+v, want ok after taking over an expired lease", row)
	}
}

// TestRunOnceReleasesLeaseOnSuccess proves the lease is actually
// released (expires_at set to now, not left at the acquire-time TTL)
// after a run completes, so another replica is not blocked for
// runTimeout+1h by a claim nobody is using anymore.
func TestRunOnceReleasesLeaseOnSuccess(t *testing.T) {
	tool := &fakeTool{stats: RunStats{SnapshotID: "abc"}}
	e, _ := testEngine(t, tool)
	ctx := context.Background()

	e.runOnce(ctx, false)

	lease, err := e.Store.Lease.Query().Where(entlease.Name(leaseName)).Only(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// AcquireLease/ReleaseLease stamp real wall-clock time (they are
	// not wired to e.Now), so compare against it rather than testNow.
	if lease.ExpiresAt.After(time.Now().Add(time.Minute)) {
		t.Errorf("lease expires_at = %v, want released near now (not still claimed for runTimeout+1h)", lease.ExpiresAt)
	}
}

func TestHooksRun(t *testing.T) {
	tool := &fakeTool{}
	e, fr := testEngine(t, tool)
	for _, hook := range []string{"before-backup", "after-backup"} {
		path := filepath.Join(e.StorageRoot, "backup", hook)
		if err := os.WriteFile(path, []byte("#!/bin/sh\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	e.runOnce(context.Background(), false)
	joined := strings.Join(fr.calls, "\n")
	if !strings.Contains(joined, "before-backup") || !strings.Contains(joined, "after-backup") {
		t.Errorf("hooks not run: %v", fr.calls)
	}
	env := strings.Join(fr.envs[0], " ")
	if !strings.Contains(env, "BACKUP_TARGET=local") {
		t.Errorf("hook env = %s", env)
	}

	// A failing before-backup hook aborts the run.
	tool = &fakeTool{}
	e, fr = testEngine(t, tool)
	hookPath := filepath.Join(e.StorageRoot, "backup", "before-backup")
	if err := os.WriteFile(hookPath, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	fr.reply(hookPath, "disk not mounted", errors.New("exit 1"))
	e.runOnce(context.Background(), false)
	row := lastRun(t, e)
	if row.Status != "error" || !strings.Contains(row.Error, "before-backup") {
		t.Errorf("run = %+v", row)
	}
	if strings.Contains(strings.Join(tool.calls, ","), "backup") {
		t.Errorf("backup ran after failed hook: %v", tool.calls)
	}
}

func TestDueLogic(t *testing.T) {
	e, _ := testEngine(t, &fakeTool{})
	ctx := context.Background()

	// Never ran: due immediately.
	if !e.due(ctx) {
		t.Error("fresh box not due")
	}
	// Recent run outside the window: not due.
	e.Store.BackupRun.Create().
		SetStartedAt(testNow.Add(-2 * time.Hour)).SetStatus("ok").SetTool("restic").
		SaveX(ctx)
	if e.due(ctx) {
		t.Error("due 2h after a run at noon")
	}
	// Catch-up when the last attempt is too old.
	e.Now = func() time.Time { return testNow.Add(27 * time.Hour) }
	if !e.due(ctx) {
		t.Error("catch-up not due after 27h")
	}
	// Nightly window: due once past the seeded minute.
	night := time.Date(2026, 7, 9, windowHour, e.nightlyMinute(), 30, 0, time.UTC)
	e.Now = func() time.Time { return night }
	if !e.due(ctx) {
		t.Error("not due in the nightly window")
	}
	// Disabled: never due.
	saveConfig(t, e, Config{Target: Target{Type: "off"}, KeepWithinDays: 3})
	if e.due(ctx) {
		t.Error("due while disabled")
	}
}

func TestPruneRuns(t *testing.T) {
	e, _ := testEngine(t, &fakeTool{})
	ctx := context.Background()
	for i := 0; i < keepRuns+5; i++ {
		e.Store.BackupRun.Create().
			SetStartedAt(testNow.Add(time.Duration(-i) * time.Hour)).
			SetStatus("ok").SetTool("restic").
			SaveX(ctx)
	}
	e.pruneRuns(ctx)
	n, err := e.Store.BackupRun.Query().Count(ctx)
	if err != nil || n != keepRuns {
		t.Errorf("rows = %d (%v)", n, err)
	}
	// The newest rows survive.
	newest := lastRun(t, e)
	if !newest.StartedAt.Equal(testNow) {
		t.Errorf("newest = %v", newest.StartedAt)
	}
}

func TestCheckpointSQLite(t *testing.T) {
	e, _ := testEngine(t, &fakeTool{})
	// A real WAL-mode database with uncheckpointed pages.
	dbPath := filepath.Join(e.StorageRoot, "control", "x.sqlite")
	if err := os.MkdirAll(filepath.Dir(dbPath), 0o755); err != nil {
		t.Fatal(err)
	}
	client, err := store.Open(store.EngineSQLite, dbPath)
	if err != nil {
		t.Fatal(err)
	}
	client.Schema.Create(context.Background())
	client.Setting.Create().SetKey("k").SetValue("v").SaveX(context.Background())

	e.checkpointSQLite(context.Background())

	// After TRUNCATE checkpointing, the WAL file is empty.
	if info, err := os.Stat(dbPath + "-wal"); err == nil && info.Size() != 0 {
		t.Errorf("wal not truncated: %d bytes", info.Size())
	}
	client.Close()
}

func TestCheckpointSkipsUnwritableDatabase(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores file permissions")
	}
	e, _ := testEngine(t, &fakeTool{})
	var logs bytes.Buffer
	e.Log = log.New(&logs, "", 0)

	// A foreign service's database this process can read but not
	// write: must be skipped quietly, not reported as a failure.
	foreign := filepath.Join(e.StorageRoot, "rav", "data.sqlite")
	if err := os.MkdirAll(filepath.Dir(foreign), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(foreign, []byte("garbage"), 0o444); err != nil {
		t.Fatal(err)
	}

	// A writable database alongside it must still be checkpointed.
	own := filepath.Join(e.StorageRoot, "control", "manager.sqlite")
	if err := os.MkdirAll(filepath.Dir(own), 0o755); err != nil {
		t.Fatal(err)
	}
	client, err := store.Open(store.EngineSQLite, own)
	if err != nil {
		t.Fatal(err)
	}
	client.Schema.Create(context.Background())
	client.Setting.Create().SetKey("k").SetValue("v").SaveX(context.Background())

	e.checkpointSQLite(context.Background())

	if !strings.Contains(logs.String(), "skipped (read-only for this process): "+foreign) {
		t.Errorf("read-only db not skipped; log:\n%s", logs.String())
	}
	if strings.Contains(logs.String(), "WAL checkpoint "+foreign+":") {
		t.Errorf("read-only db reported as checkpoint failure; log:\n%s", logs.String())
	}
	if info, err := os.Stat(own + "-wal"); err == nil && info.Size() != 0 {
		t.Errorf("own wal not truncated: %d bytes", info.Size())
	}
	client.Close()
}
