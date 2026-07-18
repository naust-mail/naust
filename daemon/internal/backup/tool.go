package backup

import (
	"context"
	"time"
)

// Snapshot is one restorable point in time, in tool-neutral form.
type Snapshot struct {
	ID   string    `json:"id"`
	Time time.Time `json:"time"`
	// Size is the full restore size in bytes, DataAdded what this
	// snapshot added to the repository; zero when the tool does not
	// report it.
	Size      int64 `json:"size,omitempty"`
	DataAdded int64 `json:"data_added,omitempty"`
	FileCount int64 `json:"file_count,omitempty"`
	// Full marks duplicity full backups (restic snapshots are all
	// logically full); informational only.
	Full bool `json:"full,omitempty"`
}

// RunStats is what one backup run reports for the run record.
type RunStats struct {
	SnapshotID string `json:"snapshot_id,omitempty"`
	Size       int64  `json:"size,omitempty"`
	DataAdded  int64  `json:"data_added,omitempty"`
	FileCount  int64  `json:"file_count,omitempty"`
}

// Tool is the restic-shaped interface both backends implement.
// Duplicity's chain mechanics (full vs incremental cadence, chain-
// granular deletion) are internal to its adapter.
type Tool interface {
	Name() string
	// Prepare recovers from any interrupted previous run (stale
	// locks, incomplete sets) and initializes the repository on first
	// use. Runs at the start of every engine run, which is how crash
	// and restart recovery stay one mechanism.
	Prepare(ctx context.Context) error
	// Backup takes one backup of the storage root.
	Backup(ctx context.Context) (RunStats, error)
	// Prune applies the retention window. A failure here must not
	// fail the run - the engine records it as a warning.
	Prune(ctx context.Context) error
	// Check verifies repository integrity.
	Check(ctx context.Context) error
	// Snapshots lists everything restorable.
	Snapshots(ctx context.Context) ([]Snapshot, error)
	// Restore extracts one snapshot into targetDir.
	Restore(ctx context.Context, snapshotID, targetDir string) error
}

// Runner executes one tool command with extra environment variables
// (KEY=VALUE), returning combined output. The engine supplies a real
// exec implementation; tests substitute a fake.
type Runner func(ctx context.Context, extraEnv []string, argv ...string) (string, error)

// ToolEnv carries everything an adapter needs.
type ToolEnv struct {
	StorageRoot string
	Config      Config
	// Passphrase is the content of secret_key.txt: restic's repo
	// password and duplicity's GPG passphrase.
	Passphrase string
	// SSHKeyPath is the identity for rsync/SFTP targets
	// (STORAGE_ROOT/backup/ssh/id_rsa).
	SSHKeyPath string
	Run        Runner
}
