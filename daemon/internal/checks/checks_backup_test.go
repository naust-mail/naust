package checks

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"naust/daemon/internal/backup"
)

func backupDeps(t *testing.T) *Deps {
	t.Helper()
	return &Deps{
		Store: testStore(t),
		Now:   func() time.Time { return testNow },
	}
}

func saveBackupConfig(t *testing.T, d *Deps, cfg backup.Config) {
	t.Helper()
	encoded, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	d.Store.Setting.Create().SetKey(backup.SettingKey).SetValue(string(encoded)).
		SaveX(context.Background())
}

func addBackupRun(t *testing.T, d *Deps, at time.Time, status, errText, warning string) {
	t.Helper()
	d.Store.BackupRun.Create().
		SetStartedAt(at).SetFinishedAt(at.Add(10 * time.Minute)).
		SetStatus(status).SetTool("restic").SetError(errText).SetWarning(warning).
		SaveX(context.Background())
}

func markKeySaved(t *testing.T, d *Deps) {
	t.Helper()
	d.Store.Setting.Create().SetKey(backup.KeySavedSettingKey).
		SetValue(testNow.Format(time.RFC3339)).SaveX(context.Background())
}

func TestBackupCheck(t *testing.T) {
	// Disabled: warning on the enabled step, the rest skipped.
	d := backupDeps(t)
	saveBackupConfig(t, d, backup.Config{Target: backup.Target{Type: "off"}, KeepWithinDays: 3})
	_, _, steps := runCheck(t, d, checkBackup)
	if steps[0].Status != StatusWarning || !strings.Contains(steps[0].Message, "disabled") {
		t.Errorf("disabled = %+v", steps[0])
	}
	for i := 1; i <= 3; i++ {
		if steps[i].Status != StatusSkipped {
			t.Errorf("step %d = %+v", i, steps[i])
		}
	}

	// Healthy: recent success, key saved: all ok, three named
	// backup steps plus the key step.
	d = backupDeps(t)
	addBackupRun(t, d, testNow.Add(-11*time.Hour), "ok", "", "")
	markKeySaved(t, d)
	status, _, steps := runCheck(t, d, checkBackup)
	if status != StatusOK {
		t.Errorf("healthy = %s %+v", status, steps)
	}
	want := []string{
		"Backups are enabled",
		"At least one backup has run",
		"A backup has succeeded within the last two days",
		"Recovery key is saved off this box",
	}
	if len(steps) != len(want) {
		t.Fatalf("steps = %+v", steps)
	}
	for i, name := range want {
		if steps[i].Name != name {
			t.Errorf("step %d = %q, want %q", i, steps[i].Name, name)
		}
	}

	// Enabled but never ran: warning.
	d = backupDeps(t)
	_, _, steps = runCheck(t, d, checkBackup)
	if steps[1].Status != StatusWarning || !strings.Contains(steps[1].Message, "No backup has run yet") {
		t.Errorf("never ran = %+v", steps[1])
	}
	// Key never saved: warning mentioning the welcome email.
	if steps[3].Status != StatusWarning || !strings.Contains(steps[3].Message, "welcome email") {
		t.Errorf("key = %+v", steps[3])
	}

	// Only failures ever: error with the tool's message.
	d = backupDeps(t)
	addBackupRun(t, d, testNow.Add(-2*time.Hour), "error", "target unreachable", "")
	_, _, steps = runCheck(t, d, checkBackup)
	if steps[2].Status != StatusError || !strings.Contains(steps[2].Message, "target unreachable") {
		t.Errorf("never succeeded = %+v", steps[2])
	}

	// Stale success: error.
	d = backupDeps(t)
	addBackupRun(t, d, testNow.Add(-72*time.Hour), "ok", "", "")
	addBackupRun(t, d, testNow.Add(-2*time.Hour), "error", "disk full", "")
	_, _, steps = runCheck(t, d, checkBackup)
	if steps[2].Status != StatusError || !strings.Contains(steps[2].Message, "disk full") {
		t.Errorf("stale = %+v", steps[2])
	}

	// Recent success but latest attempt failed: warning.
	d = backupDeps(t)
	addBackupRun(t, d, testNow.Add(-30*time.Hour), "ok", "", "")
	addBackupRun(t, d, testNow.Add(-6*time.Hour), "error", "flaky network", "")
	_, _, steps = runCheck(t, d, checkBackup)
	if steps[2].Status != StatusWarning || !strings.Contains(steps[2].Message, "flaky network") {
		t.Errorf("recent failure = %+v", steps[2])
	}

	// Success with warnings surfaces them.
	d = backupDeps(t)
	addBackupRun(t, d, testNow.Add(-3*time.Hour), "ok", "", "prune failed: stale lock")
	_, _, steps = runCheck(t, d, checkBackup)
	if steps[2].Status != StatusWarning || !strings.Contains(steps[2].Message, "stale lock") {
		t.Errorf("warned run = %+v", steps[2])
	}
}
