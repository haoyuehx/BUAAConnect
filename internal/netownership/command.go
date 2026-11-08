// Package netownership tracks the network resources (routes and system DNS
// configuration) that BUAAConnect adds itself, so they can be rolled back
// without touching configuration owned by other programs.
package netownership

import (
	"context"
	"os/exec"
	"time"
)

// commandTimeout bounds every external network-configuration command so a
// wedged `ip`/`resolvectl` process cannot block connection cleanup forever.
const commandTimeout = 10 * time.Second

// CommandRunner abstracts execution of system networking tools. It exists so
// route and DNS management can be unit-tested without root privileges or a
// live network namespace.
//
// Run must return the combined stdout/stderr of the command, matching
// exec.Cmd.CombinedOutput. Implementations should honour ctx cancellation.
type CommandRunner interface {
	Run(ctx context.Context, name string, args ...string) ([]byte, error)
}

// CommandRunnerFunc adapts a plain function to CommandRunner.
type CommandRunnerFunc func(ctx context.Context, name string, args ...string) ([]byte, error)

func (f CommandRunnerFunc) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	return f(ctx, name, args...)
}

// ExecRunner runs real system commands.
type ExecRunner struct{}

func (ExecRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).CombinedOutput()
}

func normalizeRunner(runner CommandRunner) CommandRunner {
	if runner == nil {
		return ExecRunner{}
	}
	return runner
}

func commandContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), commandTimeout)
}
