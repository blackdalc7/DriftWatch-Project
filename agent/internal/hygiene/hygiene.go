// Package hygiene runs the baseline script compiled into the agent and parses its JSON report.
//
// The scripts are embedded with go:embed, so what runs is exactly what was reviewed and built; the
// server can only ask for "hygiene.collect", never send a script.
package hygiene

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

//go:embed scripts/Test-DriftwatchBaseline.ps1
var windowsScript []byte

//go:embed scripts/check-baseline.sh
var linuxScript []byte

// Schema is the report format the server expects.
const Schema = "driftwatch.hygiene/v1"

// Script returns the embedded script and file name for a platform.
func Script(platform string) ([]byte, string, error) {
	switch platform {
	case "windows":
		return windowsScript, "Test-DriftwatchBaseline.ps1", nil
	case "linux":
		return linuxScript, "check-baseline.sh", nil
	}
	return nil, "", fmt.Errorf("no baseline script for platform %q", platform)
}

// Command builds the interpreter invocation for a script path.
func Command(ctx context.Context, platform, path string) *exec.Cmd {
	if platform == "windows" {
		return exec.CommandContext(ctx, `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
			"-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", path)
	}
	return exec.CommandContext(ctx, "/bin/bash", path)
}

// Parse validates the script output.
func Parse(out []byte) (map[string]any, error) {
	out = bytes.TrimSpace(bytes.TrimPrefix(out, []byte("\xef\xbb\xbf")))
	// PowerShell may print warnings before the JSON; take the last line that looks like an object.
	lines := strings.Split(string(out), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		line := strings.TrimSpace(lines[i])
		if !strings.HasPrefix(line, "{") {
			continue
		}
		var report map[string]any
		if err := json.Unmarshal([]byte(line), &report); err != nil {
			return nil, fmt.Errorf("baseline output is not valid JSON: %w", err)
		}
		if report["schema"] != Schema {
			return nil, fmt.Errorf("unexpected report schema %v", report["schema"])
		}
		if _, ok := report["checks"].([]any); !ok {
			return nil, errors.New("report has no checks array")
		}
		return report, nil
	}
	return nil, errors.New("baseline script printed no JSON report")
}

// Collector returns a function that writes the embedded script to the workspace, runs it and parses it.
func Collector(platform, workspace string) func(ctx context.Context) (map[string]any, error) {
	return func(ctx context.Context) (map[string]any, error) {
		body, name, err := Script(platform)
		if err != nil {
			return nil, err
		}
		dir := filepath.Join(workspace, "hygiene")
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, err
		}
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, body, 0o600); err != nil {
			return nil, err
		}
		defer os.Remove(path)
		var stdout, stderr bytes.Buffer
		cmd := Command(ctx, platform, path)
		cmd.Stdout, cmd.Stderr = &stdout, &stderr
		if err := cmd.Run(); err != nil {
			return nil, fmt.Errorf("baseline script failed: %w: %s", err, strings.TrimSpace(stderr.String()))
		}
		return Parse(stdout.Bytes())
	}
}
