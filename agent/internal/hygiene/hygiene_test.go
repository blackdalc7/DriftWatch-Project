package hygiene

import (
	"context"
	"os/exec"
	"runtime"
	"strings"
	"testing"
)

func TestParse(t *testing.T) {
	good := "WARNING: something\n{\"schema\":\"driftwatch.hygiene/v1\",\"checks\":[]}\n"
	if _, err := Parse([]byte(good)); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"", "{oops", `{"schema":"x","checks":[]}`, `{"schema":"driftwatch.hygiene/v1"}`} {
		if _, err := Parse([]byte(bad)); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestEmbeddedScripts(t *testing.T) {
	for _, p := range []string{"windows", "linux"} {
		body, _, err := Script(p)
		if err != nil || len(body) < 1000 {
			t.Fatalf("%s script missing", p)
		}
	}
	ps, _, _ := Script("windows")
	for _, forbidden := range []string{"Set-MpPreference", "Set-ItemProperty", "Remove-Item", "Invoke-Expression", "iex "} {
		if strings.Contains(string(ps), forbidden) {
			t.Errorf("baseline script must stay read-only, found %q", forbidden)
		}
	}
	if _, _, err := Script("macos"); err == nil {
		t.Error("unexpected macos script")
	}
}

func TestLinuxScriptProducesAValidReport(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("linux only")
	}
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not installed")
	}
	report, err := Collector("linux", t.TempDir())(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	ids := map[string]bool{}
	for _, c := range report["checks"].([]any) {
		check := c.(map[string]any)
		ids[check["id"].(string)] = true
		switch check["status"] {
		case "pass", "fail", "unknown":
		default:
			t.Errorf("bad status in %v", check)
		}
	}
	for _, want := range []string{"linux.auditd.running", "linux.auditd.execve_rule", "linux.ssh.root_login_disabled"} {
		if !ids[want] {
			t.Errorf("missing check %s", want)
		}
	}
}
