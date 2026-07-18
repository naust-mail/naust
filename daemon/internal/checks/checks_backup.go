package checks

import (
	"context"
	"fmt"
	"strings"
	"time"

	entsql "entgo.io/ent/dialect/sql"

	"naust/daemon/internal/backup"
	"naust/daemon/internal/store/ent"
	entbackuprun "naust/daemon/internal/store/ent/backuprun"
	entsetting "naust/daemon/internal/store/ent/setting"
)

func backupChecks() []Check {
	return []Check{{
		// The awareness layer for backups is exactly this check plus
		// the digest email it feeds: unconfigured or failing backups
		// nag the administrator on their chosen schedule, and nothing
		// ever gates on it.
		Name:        "backup",
		Title:       "Backups running",
		ShortLabel:  "backup",
		Description: "Checks that backups are turned on and that one completed successfully within the last two days, and that the recovery key needed to restore them has been saved somewhere off this box. Without a recent backup and that key, a failed machine means mail and settings are lost for good.",
		Class:       ClassMetric,
		Category:    "system", Locus: LocusNode, Tier: TierHourly,
		Run: checkBackup,
	}}
}

func checkBackup(ctx context.Context, d *Deps, _ string, r *Reporter) {
	cfg, err := backup.LoadConfig(ctx, d.Store)
	if err != nil {
		r.Step("Backup configuration can be read", func(s *StepCtx) {
			s.Failf("backup configuration could not be read: %v", err)
		})
		return
	}

	r.Step("Backups are enabled", func(s *StepCtx) {
		if !cfg.Enabled() {
			s.Warnf("Backups are disabled - if this box dies, its mail and settings are gone.")
			s.Hint("Enable on the Backups page")
		}
	})

	var last *ent.BackupRun
	r.Step("At least one backup has run", func(s *StepCtx) {
		if !cfg.Enabled() {
			s.Skipf("backups are disabled")
			return
		}
		run, err := d.Store.BackupRun.Query().
			Order(entbackuprun.ByStartedAt(entsql.OrderDesc())).
			First(ctx)
		if err != nil {
			s.Warnf("No backup has run yet. The first one starts automatically; check back shortly.")
			return
		}
		last = run
	})

	r.Step("A backup has succeeded within the last two days", func(s *StepCtx) {
		if !cfg.Enabled() {
			s.Skipf("backups are disabled")
			return
		}
		if last == nil {
			s.Skipf("no backup has run yet")
			return
		}
		lastOK, okErr := d.Store.BackupRun.Query().
			Where(entbackuprun.StatusEQ("ok")).
			Order(entbackuprun.ByStartedAt(entsql.OrderDesc())).
			First(ctx)
		age := "never"
		if okErr == nil {
			age = fmt.Sprintf("%.0fh ago", d.Now().Sub(lastOK.StartedAt).Hours())
		}
		s.Expect("a successful backup within the last two days", "last success: "+age)
		switch {
		case okErr != nil && last.Status == "error":
			s.Failf("Backups have never succeeded. Last error: %s", summarizeError(last.Error))
			s.Hint("See the Backups page for full output")
		case okErr != nil:
			s.Warnf("No backup has completed yet.")
		case d.Now().Sub(lastOK.StartedAt) > 48*time.Hour:
			msg := fmt.Sprintf("The last successful backup was %s.", lastOK.StartedAt.UTC().Format("2006-01-02"))
			if last.Status == "error" {
				msg += " Last error: " + summarizeError(last.Error)
				s.Hint("See the Backups page for full output")
			}
			s.Failf("%s", msg)
		case last.Status == "error":
			s.Warnf("The most recent backup failed (%s); the last good one was %s.", summarizeError(last.Error), age)
			s.Hint("See the Backups page for full output")
		case last.Warning != "":
			s.Warnf("The last backup succeeded with warnings: %s", summarizeError(last.Warning))
		default:
			s.Passf("%s", age)
		}
	})

	r.Step("Recovery key is saved off this box", func(s *StepCtx) {
		if !cfg.Enabled() {
			s.Skipf("backups are disabled")
			return
		}
		exists, err := d.Store.Setting.Query().
			Where(entsetting.Key(backup.KeySavedSettingKey)).Exist(ctx)
		if err != nil {
			s.Warnf("could not read the key-saved marker: %v", err)
			return
		}
		if !exists {
			s.Warnf("The backup recovery key has never been saved off this box - without it, backups cannot be restored. It is in your welcome email.")
			s.Hint("Download the restore sheet from the Backups page")
		}
	})
}

// summarizeError shortens a tool error for display in a check step.
// Backup tool errors (restic/duplicity) wrap the entire combined
// stdout/stderr of the failed command; the actual failure reason is
// almost always the last non-empty line, and the full output is
// already kept verbatim on the Backups page per-run history.
func summarizeError(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	last := strings.TrimSpace(lines[len(lines)-1])
	const maxLen = 300
	if len(last) > maxLen {
		last = last[:maxLen] + "..."
	}
	return last
}
