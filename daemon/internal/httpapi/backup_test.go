package httpapi

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"naust/daemon/internal/api"
	"naust/daemon/internal/backup"
	entsetting "naust/daemon/internal/store/ent/setting"
)

type fakeBackup struct {
	runs int
	busy bool
}

func (f *fakeBackup) RunNow()    { f.runs++ }
func (f *fakeBackup) Busy() bool { return f.busy }

func backupTestServer(t *testing.T) (*Server, *fakeBackup, string) {
	t.Helper()
	s, _ := newTestServer(t)
	fb := &fakeBackup{}
	s.Backup = fb
	root := t.TempDir()
	s.StorageRoot = root
	if err := os.MkdirAll(filepath.Join(root, "backup"), 0o755); err != nil {
		t.Fatal(err)
	}
	return s, fb, login(t, s).Token
}

func TestBackupStatusAndConfig(t *testing.T) {
	s, _, token := backupTestServer(t)
	ctx := context.Background()
	s.Backup.(*fakeBackup).busy = true

	ranAt := time.Date(2026, 7, 8, 1, 14, 0, 0, time.UTC)
	done := ranAt.Add(20 * time.Minute)
	s.Store.BackupRun.Create().
		SetStartedAt(ranAt).SetFinishedAt(done).SetStatus("ok").SetTool("restic").
		SetWarning("prune failed").
		SetStats(`{"snapshot_id":"abc123","size":4096,"file_count":7}`).
		SaveX(ctx)
	snaps, _ := json.Marshal([]backup.Snapshot{{ID: "abc123", Time: ranAt, Size: 4096, Full: true}})
	s.Store.Setting.Create().SetKey(backup.SnapshotsSettingKey).SetValue(string(snaps)).SaveX(ctx)

	w := doJSON(t, s, "GET", "/api/system/backup", token, nil)
	if w.Code != 200 {
		t.Fatalf("GET = %d %s", w.Code, w.Body)
	}
	var resp api.BackupStatusResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if !resp.Running || resp.Tool != "restic" || resp.Config.Target.Type != "local" {
		t.Errorf("resp = running=%v tool=%s target=%s", resp.Running, resp.Tool, resp.Config.Target.Type)
	}
	if len(resp.Runs) != 1 || resp.Runs[0].SnapshotID != "abc123" ||
		resp.Runs[0].Warning != "prune failed" || resp.Runs[0].FinishedAt == nil {
		t.Errorf("runs = %+v", resp.Runs)
	}
	if len(resp.Snapshots) != 1 || !resp.Snapshots[0].Full || resp.Snapshots[0].Size != 4096 {
		t.Errorf("snapshots = %+v", resp.Snapshots)
	}
	if resp.KeySavedAt != nil {
		t.Errorf("key_saved_at = %v before any download", resp.KeySavedAt)
	}

	// PUT an s3 config with credentials.
	put := api.BackupConfig{
		Target: api.BackupTargetConfig{Type: "s3", Endpoint: "s3.example.com",
			Bucket: "bkt", AccessKey: "AK", SecretKey: "SK"},
		KeepWithinDays: 7, CheckAfterBackup: true,
	}
	w = doJSON(t, s, "PUT", "/api/system/backup/config", token, put)
	if w.Code != 200 {
		t.Fatalf("PUT = %d %s", w.Code, w.Body)
	}
	if strings.Contains(w.Body.String(), "SK") {
		t.Error("secret returned in response")
	}

	// A second PUT without the secret keeps the stored one.
	put.Target.SecretKey = ""
	put.KeepWithinDays = 14
	if w = doJSON(t, s, "PUT", "/api/system/backup/config", token, put); w.Code != 200 {
		t.Fatalf("PUT2 = %d %s", w.Code, w.Body)
	}
	cfg, err := backup.LoadConfig(ctx, s.Store)
	if err != nil || cfg.Target.SecretKey != "SK" || cfg.KeepWithinDays != 14 {
		t.Errorf("stored = %+v (%v)", cfg, err)
	}

	// Invalid config rejected.
	bad := api.BackupConfig{Target: api.BackupTargetConfig{Type: "tape"}, KeepWithinDays: 3}
	if w = doJSON(t, s, "PUT", "/api/system/backup/config", token, bad); w.Code != 400 {
		t.Errorf("bad config = %d", w.Code)
	}
}

func TestBackupRunNow(t *testing.T) {
	s, fb, token := backupTestServer(t)
	if w := doJSON(t, s, "POST", "/api/system/backup/run", token, nil); w.Code != 202 || fb.runs != 1 {
		t.Errorf("run = %d, runs = %d", w.Code, fb.runs)
	}
	// Disabled: refused.
	cfgJSON, _ := json.Marshal(backup.Config{Target: backup.Target{Type: "off"}, KeepWithinDays: 3})
	s.Store.Setting.Create().SetKey(backup.SettingKey).SetValue(string(cfgJSON)).SaveX(context.Background())
	if w := doJSON(t, s, "POST", "/api/system/backup/run", token, nil); w.Code != 400 || fb.runs != 1 {
		t.Errorf("disabled run = %d, runs = %d", w.Code, fb.runs)
	}
	if w := doJSON(t, s, "POST", "/api/system/backup/run", "", nil); w.Code != 401 {
		t.Errorf("unauthenticated = %d", w.Code)
	}
}

func TestBackupKeySheet(t *testing.T) {
	s, _, token := backupTestServer(t)

	// No key on disk: 404, no marker.
	if w := doJSON(t, s, "GET", "/api/system/backup/key", token, nil); w.Code != 404 {
		t.Fatalf("keyless = %d", w.Code)
	}

	if err := os.WriteFile(filepath.Join(s.StorageRoot, "backup", "secret_key.txt"),
		[]byte("KEY-MATERIAL-12345\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	w := doJSON(t, s, "GET", "/api/system/backup/key", token, nil)
	if w.Code != 200 {
		t.Fatalf("key = %d %s", w.Code, w.Body)
	}
	body := w.Body.String()
	for _, want := range []string{"RESTORE SHEET for box.example.com", "KEY-MATERIAL-12345", "Local disk only"} {
		if !strings.Contains(body, want) {
			t.Errorf("sheet missing %q:\n%s", want, body)
		}
	}
	if cd := w.Header().Get("Content-Disposition"); !strings.Contains(cd, "restore-sheet-box.example.com.txt") {
		t.Errorf("disposition = %q", cd)
	}

	// First download set the custody marker; a second keeps it.
	row, err := s.Store.Setting.Query().
		Where(entsetting.Key(backup.KeySavedSettingKey)).Only(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	first := row.Value
	doJSON(t, s, "GET", "/api/system/backup/key", token, nil)
	row = s.Store.Setting.Query().
		Where(entsetting.Key(backup.KeySavedSettingKey)).OnlyX(context.Background())
	if row.Value != first {
		t.Errorf("marker moved on second download: %s -> %s", first, row.Value)
	}
}
