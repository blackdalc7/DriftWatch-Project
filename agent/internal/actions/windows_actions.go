//go:build windows

package actions

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"
	"unicode/utf16"

	"golang.org/x/sys/windows/registry"

	"github.com/driftwatch/agent/internal/bundle"
)

const runKeyPath = `Software\Microsoft\Windows\CurrentVersion\Run`

// shellCommand runs a full command line verbatim (cmd.exe needs its own quoting, not Go's argv quoting).
func shellCommand(ctx context.Context, line string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, `C:\Windows\System32\cmd.exe`)
	cmd.SysProcAttr = &syscall.SysProcAttr{CmdLine: line, HideWindow: true}
	return cmd
}

func runKeyCanary(r *Runner, ctx context.Context, s bundle.Step, res *Result) error {
	name := "DriftwatchCanary-" + r.Marker
	target := filepath.Join(r.Workspace, "canary-"+r.Marker+".txt") // never created, so nothing can run
	res.Observables["registry.path"] = `HKCU\` + runKeyPath + `\` + name
	res.Observables["registry.value"] = name
	key, _, err := registry.CreateKey(registry.CURRENT_USER, runKeyPath, registry.SET_VALUE|registry.QUERY_VALUE)
	if err != nil {
		if isBlocked(err) {
			res.Status = "blocked"
		}
		return err
	}
	defer key.Close()
	if err := key.SetStringValue(name, target); err != nil {
		if isBlocked(err) {
			res.Status = "blocked"
		}
		return err
	}
	r.Sleep(ctx, time.Duration(intParam(s.Params, "hold_seconds", 15))*time.Second)
	if _, _, err := key.GetStringValue(name); errors.Is(err, registry.ErrNotExist) {
		res.Status, res.Detail, res.Cleanup = "blocked", "the value was removed by a security control during the hold", "not_needed"
		return nil
	}
	if err := key.DeleteValue(name); err != nil {
		res.Cleanup = "failed"
		return err
	}
	res.Cleanup = "ok"
	res.Detail = "Run value created (pointing at a non-existent file) and removed"
	return nil
}

func scheduledTaskCanary(r *Runner, ctx context.Context, s bundle.Step, res *Result) error {
	name := "DriftwatchCanary-" + r.Marker
	create := fmt.Sprintf(`schtasks.exe /Create /TN %s /TR "cmd.exe /c exit 0" /SC ONCE /SD 01/01/2099 /ST 00:00 /F`, name)
	res.Observables["process.command_line"] = create
	schtasks := func(line string) *exec.Cmd {
		cmd := exec.CommandContext(ctx, `C:\Windows\System32\schtasks.exe`)
		cmd.SysProcAttr = &syscall.SysProcAttr{CmdLine: line, HideWindow: true}
		return cmd
	}
	if err := runCommand(ctx, res, schtasks(create)); err != nil {
		return err
	}
	if res.ExitCode != nil && *res.ExitCode != 0 {
		res.Status = "blocked"
		return nil
	}
	_ = runCommand(ctx, &Result{Observables: map[string]any{}}, schtasks(fmt.Sprintf("schtasks.exe /Change /TN %s /DISABLE", name)))
	r.Sleep(ctx, time.Duration(intParam(s.Params, "hold_seconds", 15))*time.Second)
	cleanup := &Result{Observables: map[string]any{}}
	if err := runCommand(ctx, cleanup, schtasks(fmt.Sprintf("schtasks.exe /Delete /TN %s /F", name))); err != nil ||
		cleanup.ExitCode == nil || *cleanup.ExitCode != 0 {
		res.Cleanup = "failed"
	} else {
		res.Cleanup = "ok"
	}
	res.Detail = "disabled task scheduled for 2099 was registered and deleted"
	return nil
}

// EncodedCommand returns the UTF-16LE Base64 PowerShell expects for -EncodedCommand.
func EncodedCommand(script string) string {
	units := utf16.Encode([]rune(script))
	buf := make([]byte, 0, len(units)*2)
	for _, u := range units {
		buf = append(buf, byte(u), byte(u>>8))
	}
	return base64.StdEncoding.EncodeToString(buf)
}

func encodedPowerShell(r *Runner, ctx context.Context, s bundle.Step, res *Result) error {
	encoded := EncodedCommand(fmt.Sprintf("Write-Output 'Driftwatch %s'", r.Marker))
	line := "powershell.exe -NoProfile -NonInteractive -EncodedCommand " + encoded
	res.Observables["process.command_line"] = line
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`)
	cmd.SysProcAttr = &syscall.SysProcAttr{CmdLine: line, HideWindow: true}
	if err := runCommand(ctx, res, cmd); err != nil {
		return err
	}
	if res.ExitCode != nil && *res.ExitCode != 0 {
		res.Status = "blocked" // ASR or AMSI stopped the script
	}
	return nil
}
