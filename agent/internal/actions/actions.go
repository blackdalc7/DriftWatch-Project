// Package actions executes validated catalog steps.
//
// Every executor is benign, carries the run marker somewhere a SIEM indexes, and cleans up after itself.
// Command lines are fixed strings selected by enum; the only variable part is the marker, which the
// bundle verifier has already constrained to DW-[a-f0-9]{16}.
package actions

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/blackdalc7/DriftWatch-Project/agent/internal/bundle"
)

// Result mirrors the server's StepResult model.
type Result struct {
	Index       int            `json:"index"`
	Action      string         `json:"action"`
	Status      string         `json:"status"` // executed | blocked | error | skipped
	StartedAt   string         `json:"started_at"`
	FinishedAt  string         `json:"finished_at"`
	ExitCode    *int           `json:"exit_code,omitempty"`
	Detail      string         `json:"detail"`
	Cleanup     string         `json:"cleanup"` // ok | failed | not_needed
	Observables map[string]any `json:"observables"`
	Output      map[string]any `json:"output,omitempty"`
}

// HygieneFunc runs the embedded baseline script and returns its JSON report.
type HygieneFunc func(ctx context.Context) (map[string]any, error)

// Runner executes steps for one run.
type Runner struct {
	Workspace string
	Marker    string
	RunID     string
	Platform  string
	Hygiene   HygieneFunc
	// Sleep is replaceable in tests so hold periods do not slow them down.
	Sleep func(ctx context.Context, d time.Duration)
}

func defaultSleep(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}

func now() string { return time.Now().UTC().Format("2006-01-02T15:04:05.000000Z") }

func intParam(p map[string]any, name string, def int) int {
	if v, ok := p[name].(int); ok {
		return v
	}
	return def
}

const maxDetail = 4000

func truncate(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > maxDetail {
		return s[:maxDetail] + "…"
	}
	return s
}

type executor func(r *Runner, ctx context.Context, s bundle.Step, res *Result) error

var executors = map[string]executor{
	"file.eicar_drop":              eicarDrop,
	"process.discovery":            discovery,
	"registry.run_key_canary":      runKeyCanary,
	"scheduled_task.canary":        scheduledTaskCanary,
	"persistence.autostart_canary": autostartCanary,
	"dns.sinkhole_query":           dnsSinkhole,
	"file.credential_canary_read":  credentialCanary,
	"powershell.encoded_marker":    encodedPowerShell,
	"hygiene.collect":              hygieneCollect,
}

// Supported reports whether this build has an executor for an action id (used by tests and the CLI).
func Supported(action string) bool { _, ok := executors[action]; return ok }

// Run executes one step. It never panics and always returns a result.
func (r *Runner) Run(ctx context.Context, s bundle.Step) (res Result) {
	if r.Sleep == nil {
		r.Sleep = defaultSleep
	}
	res = Result{Index: s.Index, Action: s.Action, StartedAt: now(), Cleanup: "not_needed",
		Observables: map[string]any{}}
	defer func() {
		if p := recover(); p != nil {
			res.Status, res.Detail = "error", fmt.Sprintf("executor panicked: %v", p)
		}
		res.FinishedAt = now()
	}()
	exec, ok := executors[s.Action]
	if !ok {
		res.Status, res.Detail = "error", "no executor for this action in this build"
		return res
	}
	if err := os.MkdirAll(r.Workspace, 0o750); err != nil {
		res.Status, res.Detail = "error", "cannot create workspace: "+err.Error()
		return res
	}
	if err := exec(r, ctx, s, &res); err != nil {
		if res.Status == "" {
			res.Status = "error"
		}
		res.Detail = truncate(strings.TrimSpace(res.Detail + " " + err.Error()))
	} else if res.Status == "" {
		res.Status = "executed"
	}
	return res
}

// isBlocked classifies errors that mean a security control stopped the action.
func isBlocked(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, fs.ErrPermission) {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "access is denied") || strings.Contains(msg, "virus") ||
		strings.Contains(msg, "potentially unwanted") || strings.Contains(msg, "operation not permitted") ||
		strings.Contains(msg, "blocked by")
}

// runCommand runs a fixed command line and records exit code and output.
func runCommand(ctx context.Context, res *Result, cmd *exec.Cmd) error {
	out, err := cmd.CombinedOutput()
	if cmd.ProcessState != nil {
		code := cmd.ProcessState.ExitCode()
		res.ExitCode = &code
	}
	res.Detail = truncate(string(out))
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return nil // the process ran; a non-zero exit is still "executed" and recorded in exit_code
		}
		if isBlocked(err) {
			res.Status = "blocked"
		}
		return err
	}
	return nil
}

var windowsDiscovery = map[string]string{
	"whoami_all": "whoami /all", "systeminfo": "systeminfo", "ipconfig_all": "ipconfig /all",
	"net_localgroup_admins": "net localgroup administrators", "tasklist": "tasklist",
}

var linuxDiscovery = map[string]string{
	"id": "id", "uname_a": "uname -a", "ip_addr": "ip addr", "getent_group_sudo": "getent group sudo",
	"ps_aux": "ps aux",
}

// DiscoveryCommandLine returns the exact command line for a discovery choice, or "" if unknown.
func DiscoveryCommandLine(platform, choice, marker string) string {
	if platform == "windows" {
		if c, ok := windowsDiscovery[choice]; ok {
			return fmt.Sprintf(`cmd.exe /c "%s & rem %s"`, c, marker)
		}
		return ""
	}
	if c, ok := linuxDiscovery[choice]; ok {
		return fmt.Sprintf("%s # %s", c, marker)
	}
	return ""
}

func discovery(r *Runner, ctx context.Context, s bundle.Step, res *Result) error {
	choice, _ := s.Params["command"].(string)
	line := DiscoveryCommandLine(r.Platform, choice, r.Marker)
	if line == "" {
		return fmt.Errorf("unknown discovery choice %q", choice)
	}
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	res.Observables["process.command_line"] = line
	return runCommand(ctx, res, shellCommand(ctx, line))
}

// eicarString is assembled at run time so the agent binary itself never contains the EICAR signature
// (otherwise antivirus would quarantine the agent, not the test file).
func eicarString() string {
	parts := []string{`X5O!P%@AP[4\PZX54(P^)7CC)7}$`, `EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*`}
	return parts[0] + parts[1]
}

func eicarDrop(r *Runner, ctx context.Context, s bundle.Step, res *Result) error {
	path := filepath.Join(r.Workspace, "eicar-"+r.Marker+".com")
	res.Observables["file.path"] = path
	content := eicarString()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		if isBlocked(err) {
			res.Status, res.Detail = "blocked", "write refused by the operating system or antivirus"
			return nil
		}
		return err
	}
	r.Sleep(ctx, time.Duration(intParam(s.Params, "wait_seconds", 10))*time.Second)
	data, err := os.ReadFile(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		res.Status, res.Detail, res.Cleanup = "blocked", "file was removed (quarantined) before the check", "not_needed"
		return nil
	case err != nil && isBlocked(err):
		res.Status, res.Detail = "blocked", "file exists but reading it was refused (antivirus lock)"
	case err != nil:
		return err
	case string(data) != content:
		res.Status, res.Detail = "blocked", "file content was altered (remediated)"
	default:
		res.Status, res.Detail = "executed", "file was still present and unmodified after the wait"
	}
	if rmErr := os.Remove(path); rmErr != nil && !errors.Is(rmErr, fs.ErrNotExist) {
		res.Cleanup = "failed"
	} else {
		res.Cleanup = "ok"
	}
	return nil
}

func dnsSinkhole(r *Runner, ctx context.Context, s bundle.Step, res *Result) error {
	name := strings.ToLower(strings.Replace(r.Marker, "DW-", "dw-", 1)) + ".c2-canary.invalid"
	res.Observables["dns.question.name"] = name
	count := intParam(s.Params, "count", 3)
	answers := 0
	for i := 0; i < count; i++ {
		lctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		addrs, err := net.DefaultResolver.LookupHost(lctx, name)
		cancel()
		if err == nil && len(addrs) > 0 {
			answers++
		}
		if i < count-1 {
			r.Sleep(ctx, 2*time.Second)
		}
	}
	if answers > 0 {
		// A sinkholing resolver answered: still executed, and worth noting for the analyst.
		res.Detail = fmt.Sprintf("%d of %d lookups were answered (resolver sinkhole?)", answers, count)
	} else {
		res.Detail = fmt.Sprintf("%d lookups sent; NXDOMAIN as expected for .invalid", count)
	}
	return nil
}

func credentialCanary(r *Runner, ctx context.Context, s bundle.Step, res *Result) error {
	dir := filepath.Join(r.Workspace, "canary")
	path := filepath.Join(dir, "passwords-"+r.Marker+".txt")
	res.Observables["file.path"] = path
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	body := "# Driftwatch canary " + r.Marker + ". These credentials are fake.\n" +
		"username=driftwatch-canary\npassword=not-a-real-password-" + r.RunID + "\n"
	defer func() {
		if err := os.RemoveAll(dir); err != nil {
			res.Cleanup = "failed"
		} else {
			res.Cleanup = "ok"
		}
	}()
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		if isBlocked(err) {
			res.Status = "blocked"
		}
		return err
	}
	if _, err := os.ReadFile(path); err != nil {
		if isBlocked(err) {
			res.Status, res.Detail = "blocked", "read of the canary file was refused"
			return nil
		}
		return err
	}
	res.Detail = "canary written, read back and removed"
	return nil
}

// AutostartPath is where the XDG canary is written for the current user.
func AutostartPath(home, marker string) string {
	return filepath.Join(home, ".config", "autostart", "driftwatch-"+marker+".desktop")
}

func autostartCanary(r *Runner, ctx context.Context, s bundle.Step, res *Result) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	path := AutostartPath(home, r.Marker)
	res.Observables["file.path"] = path
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	desktop := "[Desktop Entry]\nType=Application\nName=Driftwatch canary " + r.Marker +
		"\nExec=/bin/true\nHidden=true\nNoDisplay=true\nX-GNOME-Autostart-enabled=false\n"
	if err := os.WriteFile(path, []byte(desktop), 0o600); err != nil {
		if isBlocked(err) {
			res.Status = "blocked"
		}
		return err
	}
	r.Sleep(ctx, time.Duration(intParam(s.Params, "hold_seconds", 15))*time.Second)
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		res.Cleanup = "failed"
		return err
	}
	if _, err := os.Stat(path); errors.Is(err, fs.ErrNotExist) {
		res.Cleanup = "ok"
	}
	res.Detail = "autostart entry created with Exec=/bin/true and removed"
	return nil
}

func hygieneCollect(r *Runner, ctx context.Context, s bundle.Step, res *Result) error {
	if r.Hygiene == nil {
		return errors.New("no hygiene collector configured")
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	report, err := r.Hygiene(ctx)
	if err != nil {
		return err
	}
	res.Output = report
	if checks, ok := report["checks"].([]any); ok {
		res.Detail = fmt.Sprintf("%d checks collected", len(checks))
	}
	return nil
}
