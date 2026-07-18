package httpapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	entsql "entgo.io/ent/dialect/sql"

	"naust/daemon/internal/api"
	"naust/daemon/internal/backup"
	entbackuprun "naust/daemon/internal/store/ent/backuprun"
	entsetting "naust/daemon/internal/store/ent/setting"
)

// BackupRunner is the slice of *backup.Engine the API uses.
type BackupRunner interface {
	RunNow()
	Busy() bool
}

func (s *Server) handleBackupStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	cfg, err := backup.LoadConfig(ctx, s.Store)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "backup config lookup failed")
		return
	}
	runs, err := s.Store.BackupRun.Query().
		Order(entbackuprun.ByStartedAt(entsql.OrderDesc())).
		Limit(10).
		All(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "backup run lookup failed")
		return
	}

	resp := api.BackupStatusResponse{
		Config:    backupConfigToAPI(cfg.Redacted()),
		Tool:      s.backupTool(),
		Runs:      make([]api.BackupRunInfo, 0, len(runs)),
		Snapshots: []api.BackupSnapshot{},
		Running:   s.Backup.Busy(),
	}
	if pub, err := os.ReadFile(filepath.Join(s.StorageRoot, "backup", "ssh", "id_rsa.pub")); err == nil {
		resp.SSHPublicKey = strings.TrimSpace(string(pub))
	}
	for _, run := range runs {
		info := api.BackupRunInfo{
			StartedAt: run.StartedAt, FinishedAt: run.FinishedAt,
			Status: run.Status, Tool: run.Tool,
			Error: run.Error, Warning: run.Warning,
		}
		var stats backup.RunStats
		if json.Unmarshal([]byte(run.Stats), &stats) == nil {
			info.SnapshotID = stats.SnapshotID
			info.Size = stats.Size
			info.DataAdded = stats.DataAdded
			info.FileCount = stats.FileCount
		}
		resp.Runs = append(resp.Runs, info)
	}

	if row, err := s.Store.Setting.Query().
		Where(entsetting.Key(backup.SnapshotsSettingKey)).Only(ctx); err == nil {
		var snaps []backup.Snapshot
		if json.Unmarshal([]byte(row.Value), &snaps) == nil {
			for _, snap := range snaps {
				resp.Snapshots = append(resp.Snapshots, api.BackupSnapshot{
					ID: snap.ID, Time: snap.Time, Size: snap.Size,
					DataAdded: snap.DataAdded, FileCount: snap.FileCount, Full: snap.Full,
				})
			}
		}
	}
	if row, err := s.Store.Setting.Query().
		Where(entsetting.Key(backup.KeySavedSettingKey)).Only(ctx); err == nil {
		if at, err := time.Parse(time.RFC3339, row.Value); err == nil {
			resp.KeySavedAt = &at
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleBackupConfigSet(w http.ResponseWriter, r *http.Request) {
	var req api.BackupConfig
	if !decodeBody(w, r, &req) {
		return
	}
	cfg := backupConfigFromAPI(req)

	// Blank credentials on PUT mean "keep what is stored" - the GET
	// response never returns them, so an edited form comes back with
	// these fields empty.
	prev, err := backup.LoadConfig(r.Context(), s.Store)
	if err == nil && cfg.Target.Type == prev.Target.Type {
		if cfg.Target.SecretKey == "" {
			cfg.Target.SecretKey = prev.Target.SecretKey
		}
		if cfg.Target.AppKey == "" {
			cfg.Target.AppKey = prev.Target.AppKey
		}
	}
	if err := cfg.Validate(); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	encoded, err := json.Marshal(cfg)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "backup config update failed")
		return
	}
	err = s.Store.Setting.Create().
		SetKey(backup.SettingKey).
		SetValue(string(encoded)).
		OnConflictColumns(entsetting.FieldKey).
		UpdateNewValues().
		Exec(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "backup config update failed")
		return
	}
	writeJSON(w, http.StatusOK, backupConfigToAPI(cfg.Redacted()))
}

func (s *Server) handleBackupRun(w http.ResponseWriter, r *http.Request) {
	cfg, err := backup.LoadConfig(r.Context(), s.Store)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "backup config lookup failed")
		return
	}
	if !cfg.Enabled() {
		writeError(w, http.StatusBadRequest, "backups are disabled")
		return
	}
	s.Backup.RunNow()
	w.WriteHeader(http.StatusAccepted)
}

// handleBackupKey serves the restore sheet: the encryption key plus
// where the backups live - everything needed to restore onto a fresh
// box. Serving it records key_saved_at, the passive custody signal
// the backup check reads (kept at the FIRST download).
func (s *Server) handleBackupKey(w http.ResponseWriter, r *http.Request) {
	key, err := os.ReadFile(filepath.Join(s.StorageRoot, "backup", "secret_key.txt"))
	if err != nil {
		writeError(w, http.StatusNotFound, "this box has no backup encryption key")
		return
	}
	cfg, err := backup.LoadConfig(r.Context(), s.Store)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "backup config lookup failed")
		return
	}

	exists, err := s.Store.Setting.Query().
		Where(entsetting.Key(backup.KeySavedSettingKey)).Exist(r.Context())
	if err == nil && !exists {
		_ = s.Store.Setting.Create().
			SetKey(backup.KeySavedSettingKey).
			SetValue(time.Now().UTC().Format(time.RFC3339)).
			Exec(r.Context())
	}

	var b strings.Builder
	fmt.Fprintf(&b, "RESTORE SHEET for %s\n", s.PrimaryHostname)
	fmt.Fprintf(&b, "Generated %s\n\n", time.Now().UTC().Format("2006-01-02"))
	fmt.Fprintf(&b, "Backups of this server are encrypted. The files plus the key\n")
	fmt.Fprintf(&b, "below are everything needed to restore onto a fresh install.\n")
	fmt.Fprintf(&b, "Without the key, the backups are unreadable.\n\n")
	fmt.Fprintf(&b, "ENCRYPTION KEY\n\n%s\n\n", strings.TrimSpace(string(key)))
	fmt.Fprintf(&b, "BACKUP LOCATION\n\n%s\n", describeTarget(cfg.Target))
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="restore-sheet-`+s.PrimaryHostname+`.txt"`)
	w.Write([]byte(b.String()))
}

// describeTarget summarizes where backups live, without credentials
// (the sheet may end up printed or in a drawer; the key is the secret
// that matters, target credentials can be reissued).
func describeTarget(t backup.Target) string {
	switch t.Type {
	case "off":
		return "Backups are currently disabled."
	case "local":
		return "Local disk only (STORAGE_ROOT/backup/): copy that directory somewhere safe, or configure a remote target."
	case "rsync":
		return fmt.Sprintf("SFTP: %s@%s:%s", t.User, t.Host, t.Path)
	case "s3":
		return fmt.Sprintf("S3: https://%s/%s", t.Endpoint, t.Bucket)
	case "b2":
		return fmt.Sprintf("Backblaze B2 bucket: %s", t.Bucket)
	}
	return t.Type
}

func (s *Server) backupTool() string {
	if s.Conf != nil {
		if v := s.Conf("BACKUP_TOOL"); v != "" {
			return v
		}
	}
	return "restic"
}

func backupConfigToAPI(c backup.Config) api.BackupConfig {
	return api.BackupConfig{
		Target: api.BackupTargetConfig{
			Type: c.Target.Type, Host: c.Target.Host, Port: c.Target.Port,
			User: c.Target.User, Path: c.Target.Path,
			Endpoint: c.Target.Endpoint, Region: c.Target.Region, Bucket: c.Target.Bucket,
			AccessKey: c.Target.AccessKey, SecretKey: c.Target.SecretKey,
			KeyID: c.Target.KeyID, AppKey: c.Target.AppKey,
		},
		KeepWithinDays:   c.KeepWithinDays,
		CheckAfterBackup: c.CheckAfterBackup,
	}
}

func backupConfigFromAPI(c api.BackupConfig) backup.Config {
	return backup.Config{
		Target: backup.Target{
			Type: c.Target.Type, Host: c.Target.Host, Port: c.Target.Port,
			User: c.Target.User, Path: c.Target.Path,
			Endpoint: c.Target.Endpoint, Region: c.Target.Region, Bucket: c.Target.Bucket,
			AccessKey: c.Target.AccessKey, SecretKey: c.Target.SecretKey,
			KeyID: c.Target.KeyID, AppKey: c.Target.AppKey,
		},
		KeepWithinDays:   c.KeepWithinDays,
		CheckAfterBackup: c.CheckAfterBackup,
	}
}
