// Command boxctl is the Naust operator CLI (Go rewrite of the Python boxctl
// runtime commands). This binary owns the runtime/operator surface - health
// (doctor/status), break-glass recovery (recover), first-admin bootstrap - and
// shares managerd's own packages (internal/store, internal/checks, internal/auth)
// so it never re-implements or drifts from the daemon. It runs installed on a
// live box; pre-install, repo-side concerns (the docker-compose deploy wizard,
// the installer) are deliberately NOT here - they belong to the setup rewrite,
// the tool that legitimately runs from the repo.
package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"golang.org/x/term"
)

// exitCode lets a command request a specific process exit status (status uses
// the 3-valued 0/1/2 health convention). Commands set it and return nil; main
// exits with it after Execute. A returned error still exits 1.
var exitCode int

func main() {
	root := &cobra.Command{
		Use:           "boxctl",
		Short:         "Naust operator CLI",
		SilenceUsage:  true,
		SilenceErrors: true,
		// Bare `boxctl` opens the doctor TUI on an interactive terminal
		// (like the old boxctl); otherwise it prints help.
		RunE: func(cmd *cobra.Command, _ []string) error {
			if term.IsTerminal(int(os.Stdout.Fd())) {
				return runDoctor("", false)
			}
			return cmd.Help()
		},
	}
	root.AddCommand(statusCmd(), doctorCommand(), recoverCmd(), bootstrapCmd())
	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
	os.Exit(exitCode)
}
