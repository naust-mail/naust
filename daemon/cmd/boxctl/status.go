package main

import (
	"context"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"naust/daemon/internal/checkview"
	"naust/daemon/internal/liveness"
)

// statusCmd prints the daemon's stored health results as a plain, pipe-friendly
// table (status word first, for grep/awk) and exits 0/1/2 (ok/warn/err). It is a
// viewer: managerd runs the checks, boxctl reads the stored rows. If the daemon
// is unreachable it prints the liveness failures first, marks every row STALE,
// and forces exit 2 - never silently prints nothing.
func statusCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "status",
		Short:   "Print health-check results (scriptable; exit 0=ok 1=warn 2=error)",
		Args:    cobra.NoArgs,
		PreRunE: preRun,
		RunE: func(cmd *cobra.Command, _ []string) error {
			b, err := openStore()
			if err != nil {
				return err
			}
			defer b.client.Close()
			ctx := context.Background()

			probes := b.livenessConfig().Probe()
			daemonUp := liveness.AllOK(probes)
			if !daemonUp {
				for _, p := range probes {
					if !p.OK {
						fmt.Printf("%-5s %-9s %-28s %s\n", "ERR", "daemon", p.Name, p.Detail)
					}
				}
			}

			snap, err := checkview.Load(ctx, b.client)
			if err != nil {
				return err
			}
			for _, g := range snap.Groups {
				for _, r := range g.Rows {
					name := r.Name
					if r.Domain != "" {
						name = r.Name + " " + r.Domain
					}
					msg := r.Message
					if !daemonUp {
						msg = strings.TrimSpace("STALE " + msg)
					}
					fmt.Printf("%-5s %-9s %-28s %s\n", statusWord(r.Status), g.Category, name, msg)
				}
			}
			fmt.Printf("\n%d ok, %d warning, %d error, %d skipped\n", snap.OK, snap.Warning, snap.Error, snap.Skipped)

			exitCode = snap.ExitCode()
			if !daemonUp && exitCode < 2 {
				exitCode = 2
			}
			return nil
		},
	}
}

// statusWord maps a stored status to its fixed-width label.
func statusWord(s string) string {
	switch s {
	case checkview.StatusOK:
		return "OK"
	case checkview.StatusWarning:
		return "WARN"
	case checkview.StatusError:
		return "ERR"
	case checkview.StatusSkipped:
		return "SKIP"
	default:
		return strings.ToUpper(s)
	}
}
