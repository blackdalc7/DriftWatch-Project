//go:build !windows

package actions

import (
	"context"
	"errors"
	"os/exec"

	"github.com/blackdalc7/DriftWatch-Project/agent/internal/bundle"
)

var errWindowsOnly = errors.New("this action only exists on Windows")

// shellCommand runs a fixed command line through /bin/sh so the marker comment appears in the
// process command line that auditd records.
func shellCommand(ctx context.Context, line string) *exec.Cmd {
	return exec.CommandContext(ctx, "/bin/sh", "-c", line)
}

func runKeyCanary(*Runner, context.Context, bundle.Step, *Result) error        { return errWindowsOnly }
func scheduledTaskCanary(*Runner, context.Context, bundle.Step, *Result) error { return errWindowsOnly }
func encodedPowerShell(*Runner, context.Context, bundle.Step, *Result) error   { return errWindowsOnly }
