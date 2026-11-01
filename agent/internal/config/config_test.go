package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const key = "11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo="

func write(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "agent.json")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoad(t *testing.T) {
	p := write(t, `{"server_url":"https://driftwatch.lab:8443","ca_file":"ca.crt","signing_public_key":"`+key+`"}`)
	cfg, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.LabScope != "lab" || cfg.CAFile != filepath.Join(filepath.Dir(p), "ca.crt") {
		t.Errorf("defaults not applied: %+v", cfg)
	}
	if cfg.Poll(0) != 30*time.Second || cfg.Poll(10) != 10*time.Second {
		t.Error("poll interval")
	}
	cfg.PollSeconds = 7
	if cfg.Poll(30) != 7*time.Second {
		t.Error("override ignored")
	}
}

func TestLoadRejects(t *testing.T) {
	cases := map[string]string{
		`{"server_url":"http://x","ca_file":"c","signing_public_key":"` + key + `"}`:                   "https",
		`{"server_url":"https://x","signing_public_key":"` + key + `"}`:                                "ca_file",
		`{"server_url":"https://x","ca_file":"c","signing_public_key":"short"}`:                        "Ed25519",
		`{"server_url":"https://x","ca_file":"c","signing_public_key":"` + key + `","lab_scope":""}`:   "lab_scope",
		`{"server_url":"https://x","ca_file":"c","signing_public_key":"` + key + `","poll_seconds":1}`: "poll",
		`not json`: "JSON",
	}
	for body, want := range cases {
		if _, err := Load(write(t, body)); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: got %v, want %q", body, err, want)
		}
	}
	if _, err := Load(filepath.Join(t.TempDir(), "missing.json")); err == nil {
		t.Error("missing file accepted")
	}
}
