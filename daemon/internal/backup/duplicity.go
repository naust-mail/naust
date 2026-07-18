package backup

import (
	"context"
	"fmt"
	"net/url"
	"path/filepath"
	"strings"
	"time"
)

// Duplicity drives the legacy duplicity backend behind the same
// snapshot-shaped interface as restic. The chain mechanics stay in
// here: each backup set (full or incremental) presents as a snapshot
// whose ID is duplicity's set timestamp (valid for restore --time),
// and retention applies at chain granularity - remove-older-than only
// deletes chains whose newest set is past the window, so deletion
// happens in chunks. Full backups are forced on a cadence so chains
// actually age out.
type Duplicity struct {
	ToolEnv
	// Binary defaults to the management venv install.
	Binary string
}

func newDuplicity(env ToolEnv) (Tool, error) {
	return &Duplicity{ToolEnv: env}, nil
}

func (d *Duplicity) Name() string { return "duplicity" }

func (d *Duplicity) bin() string {
	if d.Binary != "" {
		return d.Binary
	}
	return "/usr/local/lib/naust/backup-venv/bin/duplicity"
}

func (d *Duplicity) cacheDir() string {
	return filepath.Join(d.StorageRoot, "backup", "cache")
}

// targetURL builds duplicity's target from the typed config.
func (d *Duplicity) targetURL() (string, error) {
	t := d.Config.Target
	switch t.Type {
	case "local":
		return "file://" + filepath.Join(d.StorageRoot, "backup", "encrypted"), nil
	case "rsync":
		// The port is deliberately NOT in the URL: duplicity accepts
		// it there but does not act on it, so it rides in the ssh
		// options instead. An absolute path needs the double slash.
		path := t.Path
		if strings.HasPrefix(path, "/") {
			path = "/" + path
		}
		return fmt.Sprintf("rsync://%s@%s/%s", t.User, t.Host, strings.TrimPrefix(path, "/")), nil
	case "s3":
		// Bucket may carry a prefix ("bucket/boxes"); the endpoint
		// goes in --s3-endpoint-url.
		return "s3://" + t.Bucket, nil
	case "b2":
		// duplicity takes B2 credentials in the URL.
		return fmt.Sprintf("b2://%s:%s@%s", t.KeyID, url.QueryEscape(t.AppKey), t.Bucket), nil
	}
	return "", fmt.Errorf("unsupported backup target for duplicity: %s", t.Type)
}

// extraArgs are the per-target flags (ported verbatim from the known-
// working Python argument builder, with the ssh key relocated).
func (d *Duplicity) extraArgs() []string {
	t := d.Config.Target
	switch t.Type {
	case "rsync":
		port := t.Port
		if port == 0 {
			port = 22
		}
		return []string{
			fmt.Sprintf("--ssh-options='-i %s -p %d'", d.SSHKeyPath, port),
			fmt.Sprintf("--rsync-options='-e \"/usr/bin/ssh -oStrictHostKeyChecking=no -oBatchMode=yes -p %d -i %s\"'", port, d.SSHKeyPath),
		}
	case "s3":
		args := []string{"--s3-endpoint-url", "https://" + t.Endpoint}
		if t.Region != "" {
			args = append(args, "--s3-region-name", t.Region)
		}
		return args
	}
	return nil
}

func (d *Duplicity) env() []string {
	vars := []string{"PASSPHRASE=" + d.Passphrase}
	if d.Config.Target.Type == "s3" {
		vars = append(vars,
			"AWS_ACCESS_KEY_ID="+d.Config.Target.AccessKey,
			"AWS_SECRET_ACCESS_KEY="+d.Config.Target.SecretKey,
			"AWS_REQUEST_CHECKSUM_CALCULATION=WHEN_REQUIRED",
			"AWS_RESPONSE_CHECKSUM_VALIDATION=WHEN_REQUIRED")
	}
	return vars
}

func (d *Duplicity) run(ctx context.Context, args ...string) (string, error) {
	target, err := d.targetURL()
	if err != nil {
		return "", err
	}
	argv := append([]string{d.bin()}, args...)
	argv = append(argv, d.extraArgs()...)
	argv = append(argv, target)
	return d.Run(ctx, d.env(), argv...)
}

// Prepare tidies up after an interrupted previous session, per
// duplicity's own manual ("necessary after a session fails or is
// aborted prematurely").
func (d *Duplicity) Prepare(ctx context.Context) error {
	_, err := d.run(ctx, "cleanup", "--verbosity", "error", "--archive-dir", d.cacheDir(), "--force")
	return err
}

func (d *Duplicity) Backup(ctx context.Context) (RunStats, error) {
	mode := "incr"
	if d.fullNeeded(ctx) {
		mode = "full"
	}
	target, err := d.targetURL()
	if err != nil {
		return RunStats{}, err
	}
	// --allow-source-mismatch: the hostname may have changed since
	// the first backup (upstream #396).
	argv := []string{d.bin(), mode,
		"--verbosity", "warning", "--no-print-statistics",
		"--archive-dir", d.cacheDir(),
		"--exclude", filepath.Join(d.StorageRoot, "backup"),
		"--exclude", filepath.Join(d.StorageRoot, "owncloud-backup"),
		"--volsize", "250",
		"--gpg-options", "'--cipher-algo=AES256'",
		"--allow-source-mismatch"}
	argv = append(argv, d.extraArgs()...)
	argv = append(argv, d.StorageRoot, target)
	if _, err := d.Run(ctx, d.env(), argv...); err != nil {
		return RunStats{}, fmt.Errorf("duplicity %s: %w", mode, err)
	}
	return RunStats{}, nil
}

// fullNeeded forces a new full backup when none exists or the newest
// one is old enough that its chain should age out of the retention
// window (the Python size-ratio heuristic needed a remote file
// listing and is deliberately dropped; the age cadence matches its
// other clause: keep_within_days * 10 + 1).
func (d *Duplicity) fullNeeded(ctx context.Context) bool {
	snaps, err := d.Snapshots(ctx)
	if err != nil {
		return true // fresh or unreachable target: full is the safe mode
	}
	newestFull := time.Time{}
	for _, s := range snaps {
		if s.Full && s.Time.After(newestFull) {
			newestFull = s.Time
		}
	}
	if newestFull.IsZero() {
		return true
	}
	cadence := time.Duration(d.Config.KeepWithinDays*10+1) * 24 * time.Hour
	return time.Since(newestFull) > cadence
}

func (d *Duplicity) Prune(ctx context.Context) error {
	_, err := d.run(ctx, "remove-older-than", fmt.Sprintf("%dD", d.Config.KeepWithinDays),
		"--verbosity", "error", "--archive-dir", d.cacheDir(), "--force")
	if err != nil {
		return fmt.Errorf("duplicity remove-older-than: %w", err)
	}
	return nil
}

// Check verifies the backup chain is intact without downloading data.
func (d *Duplicity) Check(ctx context.Context) error {
	if _, err := d.collectionStatus(ctx); err != nil {
		return fmt.Errorf("duplicity collection-status: %w", err)
	}
	return nil
}

func (d *Duplicity) collectionStatus(ctx context.Context) (string, error) {
	return d.run(ctx, "collection-status",
		"--archive-dir", d.cacheDir(),
		"--gpg-options", "'--cipher-algo=AES256'",
		"--log-fd", "1")
}

// duplicityTimeLayout is the machine-readable set timestamp
// (20260705T011422Z), which restore --time accepts verbatim.
const duplicityTimeLayout = "20060102T150405Z0700"

func (d *Duplicity) Snapshots(ctx context.Context) ([]Snapshot, error) {
	out, err := d.collectionStatus(ctx)
	if err != nil {
		return nil, fmt.Errorf("duplicity collection-status: %w", err)
	}
	var snaps []Snapshot
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || (fields[0] != "full" && fields[0] != "inc") {
			continue
		}
		at, err := time.Parse(duplicityTimeLayout, fields[1])
		if err != nil {
			continue
		}
		snaps = append(snaps, Snapshot{
			ID:   fields[1],
			Time: at,
			Full: fields[0] == "full",
		})
	}
	return snaps, nil
}

func (d *Duplicity) Restore(ctx context.Context, snapshotID, targetDir string) error {
	target, err := d.targetURL()
	if err != nil {
		return err
	}
	argv := []string{d.bin(), "restore", "--time", snapshotID,
		"--archive-dir", d.cacheDir()}
	argv = append(argv, d.extraArgs()...)
	argv = append(argv, target, targetDir)
	if _, err := d.Run(ctx, d.env(), argv...); err != nil {
		return fmt.Errorf("duplicity restore: %w", err)
	}
	return nil
}
