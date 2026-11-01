//go:build !windows

package actions

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/driftwatch/agent/internal/bundle"
	"github.com/driftwatch/agent/internal/catalog"
)

func runner(t *testing.T) *Runner {
	t.Helper()
	return &Runner{Workspace: t.TempDir(), Marker: "DW-0123456789abcdef", RunID: "0123456789abcdef",
		Platform: "linux", Sleep: func(context.Context, time.Duration) {}}
}

func TestEveryCatalogActionHasAnExecutor(t *testing.T) {
	for id := range catalog.Actions {
		if !Supported(id) {
			t.Errorf("no executor for %s", id)
		}
	}
}

func TestDiscoveryCommandLinesCarryTheMarker(t *testing.T) {
	if got := DiscoveryCommandLine("windows", "whoami_all", "DW-x"); got != `cmd.exe /c "whoami /all & rem DW-x"` {
		t.Errorf("windows line %q", got)
	}
	if got := DiscoveryCommandLine("linux", "id", "DW-x"); got != "id # DW-x" {
		t.Errorf("linux line %q", got)
	}
	if DiscoveryCommandLine("linux", "whoami_all", "DW-x") != "" {
		t.Error("windows choice accepted on linux")
	}
}

func TestDiscoveryRuns(t *testing.T) {
	r := runner(t)
	res := r.Run(context.Background(), bundle.Step{Action: "process.discovery", Params: map[string]any{"command": "id"}})
	if res.Status != "executed" || res.ExitCode == nil || *res.ExitCode != 0 || !strings.Contains(res.Detail, "uid=") {
		t.Fatalf("unexpected result %+v", res)
	}
	if res.Observables["process.command_line"] != "id # DW-0123456789abcdef" {
		t.Errorf("observable %v", res.Observables)
	}
}

func TestCanariesCleanUp(t *testing.T) {
	r := runner(t)
	t.Setenv("HOME", t.TempDir())
	for _, action := range []string{"file.credential_canary_read", "persistence.autostart_canary", "file.eicar_drop"} {
		res := r.Run(context.Background(), bundle.Step{Action: action, Params: map[string]any{}})
		if res.Status != "executed" || res.Cleanup != "ok" {
			t.Errorf("%s: %+v", action, res)
		}
		path, _ := res.Observables["file.path"].(string)
		if !strings.Contains(path, "DW-0123456789abcdef") {
			t.Errorf("%s: marker missing from %q", action, path)
		}
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Errorf("%s left %s behind", action, path)
		}
	}
}

func TestEicarQuarantineIsBlocked(t *testing.T) {
	r := runner(t)
	r.Sleep = func(context.Context, time.Duration) {
		// Simulate antivirus removing the file during the wait.
		_ = os.Remove(filepath.Join(r.Workspace, "eicar-"+r.Marker+".com"))
	}
	res := r.Run(context.Background(), bundle.Step{Action: "file.eicar_drop", Params: map[string]any{"wait_seconds": 1}})
	if res.Status != "blocked" {
		t.Fatalf("want blocked, got %+v", res)
	}
	if strings.Contains(eicarString(), " ") || len(eicarString()) != 68 {
		t.Error("EICAR string malformed")
	}
}

func TestDNSAndWindowsOnly(t *testing.T) {
	r := runner(t)
	res := r.Run(context.Background(), bundle.Step{Action: "dns.sinkhole_query", Params: map[string]any{"count": 1}})
	if res.Status != "executed" || res.Observables["dns.question.name"] != "dw-0123456789abcdef.c2-canary.invalid" {
		t.Errorf("dns: %+v", res)
	}
	res = r.Run(context.Background(), bundle.Step{Action: "registry.run_key_canary", Params: map[string]any{}})
	if res.Status != "error" {
		t.Errorf("windows-only action should error on linux: %+v", res)
	}
	res = r.Run(context.Background(), bundle.Step{Action: "nope"})
	if res.Status != "error" {
		t.Error("unknown action should error")
	}
}

func TestHygieneCollect(t *testing.T) {
	r := runner(t)
	res := r.Run(context.Background(), bundle.Step{Action: "hygiene.collect"})
	if res.Status != "error" {
		t.Error("missing collector should error")
	}
	r.Hygiene = func(context.Context) (map[string]any, error) {
		return map[string]any{"schema": "driftwatch.hygiene/v1", "checks": []any{map[string]any{}}}, nil
	}
	res = r.Run(context.Background(), bundle.Step{Action: "hygiene.collect"})
	if res.Status != "executed" || res.Output == nil || res.Detail != "1 checks collected" {
		t.Errorf("hygiene: %+v", res)
	}
}
