package backup

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"time"
)

// Restic drives the restic binary. Repository strings, environment
// variables, and the init/unlock/forget lifecycle are ported from the
// Python restic_args.py/actions.py semantics.
type Restic struct {
	ToolEnv
	// Binary defaults to "restic" (resolved via PATH).
	Binary string
}

func (r *Restic) Name() string { return "restic" }

func (r *Restic) bin() string {
	if r.Binary != "" {
		return r.Binary
	}
	return "restic"
}

// repo builds the repository string for the configured target.
func (r *Restic) repo() (string, error) {
	t := r.Config.Target
	switch t.Type {
	case "local":
		return filepath.Join(r.StorageRoot, "backup", "restic-repo"), nil
	case "rsync":
		return fmt.Sprintf("sftp:%s@%s:/%s", t.User, t.Host, strings.TrimPrefix(t.Path, "/")), nil
	case "s3":
		return fmt.Sprintf("s3:https://%s/%s", t.Endpoint, t.Bucket), nil
	case "b2":
		return fmt.Sprintf("b2:%s:", t.Bucket), nil
	}
	return "", fmt.Errorf("unsupported backup target for restic: %s", t.Type)
}

// env builds the credential environment for the tool process.
func (r *Restic) env() []string {
	vars := []string{"RESTIC_PASSWORD=" + r.Passphrase}
	t := r.Config.Target
	switch t.Type {
	case "s3":
		vars = append(vars,
			"AWS_ACCESS_KEY_ID="+t.AccessKey,
			"AWS_SECRET_ACCESS_KEY="+t.SecretKey)
		if t.Region != "" {
			vars = append(vars, "AWS_DEFAULT_REGION="+t.Region)
		}
	case "b2":
		vars = append(vars,
			"B2_ACCOUNT_ID="+t.KeyID,
			"B2_ACCOUNT_KEY="+t.AppKey)
	}
	return vars
}

// baseArgs are common flags for every invocation.
func (r *Restic) baseArgs() []string {
	args := []string{"--cache-dir", filepath.Join(r.StorageRoot, "backup", "restic-cache")}
	t := r.Config.Target
	if t.Type == "rsync" {
		port := t.Port
		if port == 0 {
			port = 22
		}
		args = append(args, "-o", fmt.Sprintf(
			"sftp.command=ssh -i %s -p %d -oStrictHostKeyChecking=no -oBatchMode=yes %s@%s -s sftp",
			r.SSHKeyPath, port, t.User, t.Host))
	}
	return args
}

func (r *Restic) run(ctx context.Context, args ...string) (string, error) {
	repo, err := r.repo()
	if err != nil {
		return "", err
	}
	argv := append([]string{r.bin(), "-r", repo}, args...)
	argv = append(argv, r.baseArgs()...)
	return r.Run(ctx, r.env(), argv...)
}

// Prepare initializes the repository on first use and clears stale
// locks from interrupted runs. restic init is atomic by design (the
// config object is written last), so a crashed init just reads as
// "not initialized yet" and is retried here.
func (r *Restic) Prepare(ctx context.Context) error {
	out, err := r.run(ctx, "snapshots", "--json")
	if err == nil {
		_, uerr := r.run(ctx, "unlock")
		return uerr
	}
	// restic's specific first-run signature; anything else (auth,
	// network, wrong password) must not be masked as "needs init".
	if strings.Contains(out, "Is there a repository at the following location") ||
		strings.Contains(out, "unable to open config file") {
		_, err := r.run(ctx, "init")
		return err
	}
	return fmt.Errorf("backup repository is not usable: %w", err)
}

func (r *Restic) Backup(ctx context.Context) (RunStats, error) {
	out, err := r.run(ctx, "backup", "--json",
		"--exclude", filepath.Join(r.StorageRoot, "backup"),
		"--exclude", filepath.Join(r.StorageRoot, "owncloud-backup"),
		r.StorageRoot)
	if err != nil {
		return RunStats{}, fmt.Errorf("restic backup: %w", err)
	}
	return parseResticSummary(out), nil
}

// parseResticSummary extracts the final summary line of restic's
// --json stream. A missing summary yields zero stats, not an error -
// the backup itself succeeded.
func parseResticSummary(out string) RunStats {
	var stats RunStats
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var msg struct {
			MessageType         string `json:"message_type"`
			SnapshotID          string `json:"snapshot_id"`
			DataAdded           int64  `json:"data_added"`
			TotalBytesProcessed int64  `json:"total_bytes_processed"`
			TotalFilesProcessed int64  `json:"total_files_processed"`
		}
		if json.Unmarshal([]byte(line), &msg) != nil || msg.MessageType != "summary" {
			continue
		}
		stats = RunStats{
			SnapshotID: msg.SnapshotID,
			Size:       msg.TotalBytesProcessed,
			DataAdded:  msg.DataAdded,
			FileCount:  msg.TotalFilesProcessed,
		}
	}
	return stats
}

// Prune applies the retention window. One unlock-and-retry on lock
// contention, matching the Python lifecycle.
func (r *Restic) Prune(ctx context.Context) error {
	args := []string{"forget", "--keep-within", fmt.Sprintf("%dd", r.Config.KeepWithinDays), "--prune"}
	out, err := r.run(ctx, args...)
	if err == nil {
		return nil
	}
	if strings.Contains(out, "unable to create lock") || strings.Contains(out, "already locked") {
		if _, uerr := r.run(ctx, "unlock"); uerr == nil {
			if _, err = r.run(ctx, args...); err == nil {
				return nil
			}
		}
	}
	return fmt.Errorf("restic forget --prune: %w", err)
}

func (r *Restic) Check(ctx context.Context) error {
	if _, err := r.run(ctx, "check"); err != nil {
		return fmt.Errorf("restic check: %w", err)
	}
	return nil
}

func (r *Restic) Snapshots(ctx context.Context) ([]Snapshot, error) {
	out, err := r.run(ctx, "snapshots", "--json")
	if err != nil {
		return nil, fmt.Errorf("restic snapshots: %w", err)
	}
	var raw []struct {
		ShortID string    `json:"short_id"`
		ID      string    `json:"id"`
		Time    time.Time `json:"time"`
		Summary *struct {
			TotalBytesProcessed int64 `json:"total_bytes_processed"`
			DataAdded           int64 `json:"data_added"`
			TotalFilesProcessed int64 `json:"total_files_processed"`
		} `json:"summary"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &raw); err != nil {
		return nil, fmt.Errorf("restic snapshots output: %w", err)
	}
	snaps := make([]Snapshot, 0, len(raw))
	for _, s := range raw {
		id := s.ShortID
		if id == "" {
			id = s.ID
		}
		snap := Snapshot{ID: id, Time: s.Time, Full: true}
		if s.Summary != nil {
			snap.Size = s.Summary.TotalBytesProcessed
			snap.DataAdded = s.Summary.DataAdded
			snap.FileCount = s.Summary.TotalFilesProcessed
		}
		snaps = append(snaps, snap)
	}
	return snaps, nil
}

func (r *Restic) Restore(ctx context.Context, snapshotID, targetDir string) error {
	if _, err := r.run(ctx, "restore", snapshotID, "--target", targetDir); err != nil {
		return fmt.Errorf("restic restore: %w", err)
	}
	return nil
}
