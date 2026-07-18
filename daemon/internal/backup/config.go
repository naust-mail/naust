// Package backup runs the nightly box backup. It is the Go owner of
// what daily_tasks.py's backup step did: one engine scheduled inside
// managerd (identical in Docker and on bare metal), driving one of
// two tools - restic (the default) or duplicity (legacy) - through a
// restic-shaped interface: snapshots, a retention window, one nightly
// run, restore. Tool-specific quirks (duplicity's chains) stay inside
// the adapters and never surface in config or API.
//
// Configuration lives in the store like everything else; the store is
// itself inside every backup, so a restored box comes back with all
// of its configuration. The single fact a human must hold is the
// encryption key file (secret_key.txt): backup files plus that key
// restore a box completely, with no other dependency.
package backup

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"naust/daemon/internal/store/ent"
	entsetting "naust/daemon/internal/store/ent/setting"
)

// SettingKey is the store key holding the JSON-encoded Config.
const SettingKey = "backup"

// KeySavedSettingKey records (RFC3339) when the restore sheet was
// first downloaded - the passive key-custody signal the backup check
// reads. Never a gate: the fix for "never saved" is one download.
const KeySavedSettingKey = "backup_key_saved_at"

// SnapshotsSettingKey caches the snapshot inventory (JSON []Snapshot)
// refreshed after each successful run, so the panel never waits on a
// remote listing.
const SnapshotsSettingKey = "backup_snapshots"

// Target says where backups go. Exactly the fields for the chosen
// type are used; credentials are typed fields, not URL-encoded blobs.
type Target struct {
	// Type: off (backups disabled), local (external copy is the
	// operator's job), rsync (SFTP to another host), s3, b2.
	Type string `json:"type"`

	// rsync (SFTP).
	Host string `json:"host,omitempty"`
	Port int    `json:"port,omitempty"`
	User string `json:"user,omitempty"`
	Path string `json:"path,omitempty"`

	// s3: endpoint host (e.g. s3.eu-central-1.amazonaws.com), bucket
	// plus optional prefix as "bucket/prefix", and the key pair.
	Endpoint  string `json:"endpoint,omitempty"`
	Region    string `json:"region,omitempty"`
	Bucket    string `json:"bucket,omitempty"`
	AccessKey string `json:"access_key,omitempty"`
	SecretKey string `json:"secret_key,omitempty"`

	// b2: Bucket is shared with s3 above; the B2 key pair.
	KeyID  string `json:"key_id,omitempty"`
	AppKey string `json:"app_key,omitempty"`
}

// Config is the administrator's backup configuration.
type Config struct {
	Target Target `json:"target"`
	// KeepWithinDays is the retention window: snapshots newer than
	// this are kept (restic forget --keep-within; duplicity honors it
	// at chain granularity, so deletion there happens in chunks).
	KeepWithinDays int `json:"keep_within_days"`
	// CheckAfterBackup runs the tool's integrity check after each
	// successful backup.
	CheckAfterBackup bool `json:"check_after_backup"`
}

// DefaultConfig is a fresh box: local backups, 3-day window, checked.
func DefaultConfig() Config {
	return Config{
		Target:           Target{Type: "local"},
		KeepWithinDays:   3,
		CheckAfterBackup: true,
	}
}

// Enabled reports whether backups run at all.
func (c Config) Enabled() bool { return c.Target.Type != "off" }

func (c Config) Validate() error {
	t := c.Target
	switch t.Type {
	case "off", "local":
	case "rsync":
		if t.Host == "" || t.User == "" || t.Path == "" {
			return errors.New("rsync target needs host, user, and path")
		}
		if t.Port < 0 || t.Port > 65535 {
			return errors.New("invalid port")
		}
	case "s3":
		if t.Endpoint == "" || t.Bucket == "" {
			return errors.New("s3 target needs endpoint and bucket")
		}
		if t.AccessKey == "" || t.SecretKey == "" {
			return errors.New("s3 target needs access_key and secret_key")
		}
	case "b2":
		if t.Bucket == "" || t.KeyID == "" || t.AppKey == "" {
			return errors.New("b2 target needs bucket, key_id, and app_key")
		}
	default:
		return fmt.Errorf("unknown target type %q", t.Type)
	}
	for _, s := range []string{t.Host, t.User, t.Path, t.Endpoint, t.Region, t.Bucket, t.AccessKey, t.SecretKey, t.KeyID, t.AppKey} {
		if strings.ContainsAny(s, "\n\r") {
			return errors.New("target fields must not contain newlines")
		}
	}
	if c.KeepWithinDays < 1 || c.KeepWithinDays > 3650 {
		return errors.New("keep_within_days must be between 1 and 3650")
	}
	return nil
}

// Redacted strips credentials for API responses. The admin re-enters
// them on change, same as the DNS provider tokens.
func (c Config) Redacted() Config {
	c.Target.SecretKey = ""
	c.Target.AppKey = ""
	return c
}

// LoadConfig reads the stored configuration, or the default when none
// was ever saved.
func LoadConfig(ctx context.Context, store *ent.Client) (Config, error) {
	row, err := store.Setting.Query().
		Where(entsetting.Key(SettingKey)).
		Only(ctx)
	if ent.IsNotFound(err) {
		return DefaultConfig(), nil
	}
	if err != nil {
		return Config{}, err
	}
	cfg := DefaultConfig()
	if err := json.Unmarshal([]byte(row.Value), &cfg); err != nil {
		return Config{}, fmt.Errorf("%s setting: %w", SettingKey, err)
	}
	return cfg, nil
}
