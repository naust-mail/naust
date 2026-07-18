package helper

import (
	"context"
	"fmt"
	"os"
	"os/exec"
)

// Runner executes a fixed argv and returns its combined output. There is
// deliberately no shell anywhere: argv[0] is an absolute program path and
// arguments are passed as-is.
type Runner interface {
	Run(ctx context.Context, argv []string, extraEnv []string) (string, error)
}

// Deps carries the execution environment into intent handlers. Tests
// substitute a recording Runner and a temp-dir Root.
type Deps struct {
	Run Runner
	// Root is prefixed to every baked-in file path. Empty in production;
	// tests point it at a temp dir.
	Root string
}

// ExecRunner runs commands for real.
type ExecRunner struct{}

func (ExecRunner) Run(ctx context.Context, argv []string, extraEnv []string) (string, error) {
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Env = append(os.Environ(), extraEnv...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("%s: %w: %s", argv[0], err, truncateOutput(out))
	}
	return string(out), nil
}

func truncateOutput(out []byte) string {
	const cap = 512
	if len(out) > cap {
		out = out[:cap]
	}
	return string(out)
}
