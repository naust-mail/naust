package backup

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"io/fs"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	entsql "entgo.io/ent/dialect/sql"

	"naust/daemon/internal/store"
	"naust/daemon/internal/store/ent"
	entbackuprun "naust/daemon/internal/store/ent/backuprun"
	entsetting "naust/daemon/internal/store/ent/setting"
)

const (
	tickEvery    = time.Minute
	startupDelay = 2 * time.Minute
	// runTimeout bounds one whole run; first uploads of a large mail
	// store legitimately take hours.
	runTimeout = 12 * time.Hour
	keepRuns   = 30
	// leaseName is the store lease that keeps replicas from backing
	// up the same repository concurrently.
	leaseName = "backup"
	// catchupAfter replaces cron's fixed schedule semantics: whenever
	// the last attempt is older than this, run now regardless of the
	// nightly window (covers downtime, exactly like a persistent
	// timer, identically in Docker and on bare metal).
	catchupAfter = 26 * time.Hour
	// windowHour is the nightly run hour (local time); the minute is
	// seeded from the hostname so fleets do not thunder in unison.
	windowHour = 1
)

// Engine schedules and runs backups inside managerd. All state lives
// in the store (BackupRun rows, snapshot cache setting); the engine
// itself is disposable, and an interrupted run is recovered by the
// next run's Prepare.
type Engine struct {
	Store       *ent.Client
	StorageRoot string
	// Conf resolves box configuration (BACKUP_TOOL). Nil = defaults.
	Conf func(key string) string
	// Hostname seeds the nightly minute.
	Hostname string
	// Runner executes tool commands; nil = real exec.
	Runner Runner
	// NewTool builds the adapter for a tool name; nil = the real
	// adapters. Tests substitute fakes.
	NewTool func(env ToolEnv, name string) (Tool, error)
	Now     func() time.Time
	Log     *log.Logger

	kick   chan struct{}
	manual atomic.Int32
	busy   atomic.Int32
	runMu  sync.Mutex
}

func (e *Engine) fillDefaults() {
	if e.Runner == nil {
		e.Runner = execRunner
	}
	if e.NewTool == nil {
		e.NewTool = newTool
	}
	if e.Now == nil {
		e.Now = time.Now
	}
	if e.Log == nil {
		e.Log = log.New(os.Stderr, "", log.LstdFlags)
	}
}

// execRunner runs one tool command, inheriting the process
// environment plus the tool's credential variables.
func execRunner(ctx context.Context, extraEnv []string, argv ...string) (string, error) {
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Env = append(os.Environ(), extraEnv...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("%s: %w: %s", argv[0], err, out)
	}
	return string(out), nil
}

// newTool builds the adapter for the configured BACKUP_TOOL.
func newTool(env ToolEnv, name string) (Tool, error) {
	switch name {
	case "", "restic":
		return &Restic{ToolEnv: env}, nil
	case "duplicity":
		return newDuplicity(env)
	}
	return nil, fmt.Errorf("unknown BACKUP_TOOL %q", name)
}

func (e *Engine) toolName() string {
	if e.Conf != nil {
		if v := e.Conf("BACKUP_TOOL"); v != "" {
			return v
		}
	}
	return "restic"
}

// RunNow queues a manual run. Never blocks.
func (e *Engine) RunNow() {
	e.manual.Add(1)
	e.busy.Add(1)
	select {
	case e.kick <- struct{}{}:
	default:
	}
}

// Busy reports whether a run is executing or queued.
func (e *Engine) Busy() bool { return e.busy.Load() > 0 }

// Start runs the scheduler until ctx is cancelled. Call once.
func (e *Engine) Start(ctx context.Context) {
	e.fillDefaults()
	e.kick = make(chan struct{}, 1)
	e.reconcileStaleRuns(ctx)
	go func() {
		t := time.NewTimer(startupDelay)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			case <-e.kick:
			}
			if n := e.manual.Swap(0); n > 0 {
				e.runOnce(ctx, true)
				e.busy.Add(-n)
			} else if e.due(ctx) {
				e.busy.Add(1)
				e.runOnce(ctx, false)
				e.busy.Add(-1)
			}
			t.Reset(tickEvery)
		}
	}()
}

// reconcileStaleRuns cleans up BackupRun rows this process finds stuck
// at "running" from a previous life (the process was killed or crashed
// mid-backup, so runOnce never reached complete()). It only touches
// them when the backup lease is free - a held lease means a run is
// genuinely in progress, possibly on another replica, and must be left
// alone. A short-TTL acquire-then-release is used purely as a "is
// anyone actively backing up right now" check.
func (e *Engine) reconcileStaleRuns(ctx context.Context) {
	got, err := store.AcquireLease(ctx, e.Store, leaseName, time.Minute)
	if err != nil || !got {
		return
	}
	defer func() {
		if err := store.ReleaseLease(ctx, e.Store, leaseName); err != nil {
			e.Log.Printf("backup: release lease: %v", err)
		}
	}()
	n, err := e.Store.BackupRun.Update().
		Where(entbackuprun.StatusEQ("running")).
		SetStatus("error").
		SetFinishedAt(e.Now()).
		SetError("backup process was interrupted (crash or restart) before this run finished").
		Save(ctx)
	if err != nil {
		e.Log.Printf("backup: reconcile stale runs: %v", err)
		return
	}
	if n > 0 {
		e.Log.Printf("backup: marked %d stale running run(s) as failed after restart", n)
	}
}

// nightlyMinute spreads fleets across the window hour.
func (e *Engine) nightlyMinute() int {
	h := fnv.New32a()
	h.Write([]byte(e.Hostname))
	return int(h.Sum32() % 60)
}

// due reports whether a scheduled run should start now: never ran,
// last attempt too old (catch-up), or inside the nightly window.
func (e *Engine) due(ctx context.Context) bool {
	cfg, err := LoadConfig(ctx, e.Store)
	if err != nil || !cfg.Enabled() {
		return false
	}
	last, err := e.Store.BackupRun.Query().
		Order(entbackuprun.ByStartedAt(entsql.OrderDesc())).
		First(ctx)
	if ent.IsNotFound(err) {
		return true // fresh box: take the first backup right away
	}
	if err != nil {
		return false
	}
	now := e.Now()
	if now.Sub(last.StartedAt) > catchupAfter {
		return true
	}
	return now.Hour() == windowHour && now.Minute() >= e.nightlyMinute() &&
		now.Sub(last.StartedAt) > 2*time.Hour
}

// runOnce executes one backup run end to end and records it.
func (e *Engine) runOnce(ctx context.Context, manual bool) {
	e.runMu.Lock()
	defer e.runMu.Unlock()

	cfg, err := LoadConfig(ctx, e.Store)
	if err != nil {
		e.Log.Printf("backup: load config: %v", err)
		return
	}
	if !cfg.Enabled() {
		if manual {
			e.Log.Printf("backup: manual run requested but backups are disabled")
		}
		return
	}

	ctx, cancel := context.WithTimeout(ctx, runTimeout)
	defer cancel()

	// One run per store, not per process: replicas coordinate through
	// this lease so concurrent restic/duplicity invocations never hit
	// the repository together. The TTL outlives runTimeout so only a
	// crashed holder's claim ever lapses mid-run; normal completion
	// releases it (before cancel, so the context is still live).
	got, err := store.AcquireLease(ctx, e.Store, leaseName, runTimeout+time.Hour)
	if err != nil {
		e.Log.Printf("backup: lease: %v", err)
		return
	}
	if !got {
		e.Log.Printf("backup: another process is already running backups, skipping")
		return
	}
	defer func() {
		if err := store.ReleaseLease(ctx, e.Store, leaseName); err != nil {
			e.Log.Printf("backup: release lease: %v", err)
		}
	}()

	toolName := e.toolName()
	row, err := e.Store.BackupRun.Create().
		SetStartedAt(e.Now()).
		SetStatus("running").
		SetTool(toolName).
		Save(ctx)
	if err != nil {
		e.Log.Printf("backup: record run: %v", err)
		return
	}
	fail := func(err error) {
		e.Log.Printf("backup: %v", err)
		e.complete(ctx, row, "error", err.Error(), nil, RunStats{})
	}

	passphrase, err := os.ReadFile(filepath.Join(e.StorageRoot, "backup", "secret_key.txt"))
	if err != nil {
		fail(fmt.Errorf("read encryption key: %w", err))
		return
	}
	tool, err := e.NewTool(ToolEnv{
		StorageRoot: e.StorageRoot,
		Config:      cfg,
		Passphrase:  strings.TrimSpace(string(passphrase)),
		SSHKeyPath:  filepath.Join(e.StorageRoot, "backup", "ssh", "id_rsa"),
		Run:         e.Runner,
	}, toolName)
	if err != nil {
		fail(err)
		return
	}

	if err := tool.Prepare(ctx); err != nil {
		fail(fmt.Errorf("prepare: %w", err))
		return
	}
	e.checkpointSQLite(ctx)
	if err := e.runHook(ctx, "before-backup", cfg); err != nil {
		fail(fmt.Errorf("before-backup hook: %w", err))
		return
	}

	stats, err := tool.Backup(ctx)
	if err != nil {
		fail(err)
		return
	}

	// Everything after a successful backup is best-effort: a dirty
	// retention window or a failed integrity check must not mark the
	// just-taken backup as failed, but must surface as a warning the
	// backup status check (and so the digest email) reports.
	var warnings []string
	warn := func(err error) {
		e.Log.Printf("backup: WARNING: %v", err)
		warnings = append(warnings, err.Error())
	}
	if err := tool.Prune(ctx); err != nil {
		warn(err)
	}
	if cfg.CheckAfterBackup {
		if err := tool.Check(ctx); err != nil {
			warn(err)
		}
	}
	if err := e.runHook(ctx, "after-backup", cfg); err != nil {
		warn(fmt.Errorf("after-backup hook: %w", err))
	}
	if snaps, err := tool.Snapshots(ctx); err != nil {
		warn(fmt.Errorf("refresh snapshot list: %w", err))
	} else if err := e.cacheSnapshots(ctx, snaps); err != nil {
		warn(fmt.Errorf("cache snapshot list: %w", err))
	}

	e.complete(ctx, row, "ok", "", warnings, stats)
	e.pruneRuns(ctx)
}

func (e *Engine) complete(ctx context.Context, row *ent.BackupRun, status, errText string, warnings []string, stats RunStats) {
	statsJSON, err := json.Marshal(stats)
	if err != nil {
		statsJSON = []byte("{}")
	}
	err = row.Update().
		SetFinishedAt(e.Now()).
		SetStatus(status).
		SetError(errText).
		SetWarning(strings.Join(warnings, "; ")).
		SetStats(string(statsJSON)).
		Exec(ctx)
	if err != nil {
		e.Log.Printf("backup: complete run: %v", err)
	}
}

func (e *Engine) cacheSnapshots(ctx context.Context, snaps []Snapshot) error {
	encoded, err := json.Marshal(snaps)
	if err != nil {
		return err
	}
	return e.Store.Setting.Create().
		SetKey(SnapshotsSettingKey).
		SetValue(string(encoded)).
		OnConflictColumns(entsetting.FieldKey).
		UpdateNewValues().
		Exec(ctx)
}

func (e *Engine) pruneRuns(ctx context.Context) {
	rows, err := e.Store.BackupRun.Query().
		Order(entbackuprun.ByStartedAt(entsql.OrderDesc())).
		Offset(keepRuns).
		All(ctx)
	if err != nil || len(rows) == 0 {
		return
	}
	ids := make([]int, len(rows))
	for i, r := range rows {
		ids[i] = r.ID
	}
	if _, err := e.Store.BackupRun.Delete().Where(entbackuprun.IDIn(ids...)).Exec(ctx); err != nil {
		e.Log.Printf("backup: prune runs: %v", err)
	}
}

// runHook executes an operator hook script when present
// (STORAGE_ROOT/backup/before-backup, after-backup), with the target
// type exposed as BACKUP_TARGET.
func (e *Engine) runHook(ctx context.Context, name string, cfg Config) error {
	path := filepath.Join(e.StorageRoot, "backup", name)
	if _, err := os.Stat(path); err != nil {
		return nil
	}
	_, err := e.Runner(ctx, []string{"BACKUP_TARGET=" + cfg.Target.Type}, path)
	return err
}

// checkpointSQLite flushes the WAL of every SQLite database under the
// storage root (our own store included) so the tool's file scan sees
// consistent database files. Failures are logged, never fatal.
func (e *Engine) checkpointSQLite(ctx context.Context) {
	backupDir := filepath.Join(e.StorageRoot, "backup")
	_ = filepath.WalkDir(e.StorageRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if path == backupDir {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".sqlite") {
			return nil
		}
		// Databases owned by other services (webmail, file storage)
		// are readable for the file scan but not writable by this
		// process, and a checkpoint needs write access. Skip them
		// quietly - they back up crash-consistent - so real failures
		// on our own databases stay loud.
		if f, err := os.OpenFile(path, os.O_RDWR, 0); err != nil {
			if errors.Is(err, fs.ErrPermission) {
				e.Log.Printf("backup: WAL checkpoint skipped (read-only for this process): %s", path)
				return nil
			}
		} else {
			f.Close()
		}
		if err := checkpointOne(ctx, path); err != nil {
			e.Log.Printf("backup: WAL checkpoint %s: %v", path, err)
		}
		return nil
	})
}

func checkpointOne(ctx context.Context, path string) error {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return err
	}
	defer db.Close()
	if _, err := db.ExecContext(ctx, "PRAGMA busy_timeout=10000"); err != nil {
		return err
	}
	_, err = db.ExecContext(ctx, "PRAGMA wal_checkpoint(TRUNCATE)")
	return err
}
