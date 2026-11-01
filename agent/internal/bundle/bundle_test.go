package bundle

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

type fixture struct {
	PublicKey     string `json:"public_key"`
	AgentID       string `json:"agent_id"`
	Now           string `json:"now"`
	TestBundle    Signed `json:"test_bundle"`
	HygieneBundle Signed `json:"hygiene_bundle"`
}

func load(t *testing.T) (fixture, Expect) {
	t.Helper()
	data, err := os.ReadFile("testdata/python_bundles.json")
	if err != nil {
		t.Fatal(err)
	}
	var f fixture
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatal(err)
	}
	pub, _ := base64.StdEncoding.DecodeString(f.PublicKey)
	now, _ := time.Parse(time.RFC3339, f.Now)
	return f, Expect{PublicKey: pub, AgentID: f.AgentID, Platform: "linux", Scope: "lab", Now: now}
}

// TestVerifiesPythonSignedBundles proves the Go verifier accepts exactly what the server signs.
func TestVerifiesPythonSignedBundles(t *testing.T) {
	f, want := load(t)
	task, err := Verify(f.TestBundle, want)
	if err != nil {
		t.Fatal(err)
	}
	if task.Marker != "DW-3f9c2a7b1e5d4c86" || task.Validated[0].Action != "process.discovery" {
		t.Fatalf("unexpected task %+v", task)
	}
	if f.TestBundle.KeyID != KeyID(want.PublicKey) {
		t.Errorf("key id mismatch: %s vs %s", f.TestBundle.KeyID, KeyID(want.PublicKey))
	}
	h, err := Verify(f.HygieneBundle, want)
	if err != nil || h.Kind != "hygiene" {
		t.Fatalf("hygiene bundle: %v", err)
	}
}

func TestRefusals(t *testing.T) {
	f, want := load(t)
	check := func(name string, b Signed, e Expect, substr string) {
		t.Helper()
		_, err := Verify(b, e)
		if err == nil || !strings.Contains(err.Error(), substr) {
			t.Errorf("%s: got %v, want error containing %q", name, err, substr)
		}
	}
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	e := want
	e.PublicKey = other
	check("wrong key", f.TestBundle, e, "bad signature")
	e = want
	e.AgentID = "agt_someoneelse"
	check("other agent", f.TestBundle, e, "not agt_someoneelse")
	e = want
	e.Platform = "windows"
	check("platform", f.TestBundle, e, "platform")
	e = want
	e.Scope = "prod"
	check("scope", f.TestBundle, e, "lab scope")
	e = want
	e.Now = want.Now.Add(2 * time.Hour)
	check("expired", f.TestBundle, e, "expired")
	e = want
	e.Now = want.Now.Add(-time.Hour)
	check("future", f.TestBundle, e, "future")
	e = want
	e.PublicKey = nil
	check("no key", f.TestBundle, e, "pinned")

	tampered := f.TestBundle
	raw, _ := base64.StdEncoding.DecodeString(tampered.Payload)
	tampered.Payload = base64.StdEncoding.EncodeToString([]byte(strings.Replace(string(raw), `"id"`, `"ps_aux"`, 1)))
	check("tampered payload", tampered, want, "bad signature")
	check("garbage", Signed{Payload: "!!", Signature: "x"}, want, "base64")
}

// sign builds a bundle with an arbitrary payload, to test checks that come after the signature.
func sign(t *testing.T, priv ed25519.PrivateKey, payload map[string]any) Signed {
	t.Helper()
	raw, _ := json.Marshal(payload)
	return Signed{Payload: base64.StdEncoding.EncodeToString(raw),
		Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(priv, raw))}
}

func TestSemanticChecksAfterSignature(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Date(2026, 10, 30, 14, 0, 0, 0, time.UTC)
	want := Expect{PublicKey: pub, AgentID: "agt_1", Platform: "linux", Scope: "lab", Now: now}
	base := func() map[string]any {
		return map[string]any{"version": 1, "kind": "test", "run_id": "0123456789abcdef",
			"marker": "DW-0123456789abcdef", "agent_id": "agt_1", "platform": "linux", "scope": "lab",
			"test_id": "dw-x", "test_version": 1, "issued_at": "2026-10-30T13:59:00.000000Z",
			"expires_at": "2026-10-30T14:10:00.000000Z",
			"steps":      []map[string]any{{"index": 0, "action": "process.discovery", "params": map[string]any{"command": "id"}}}}
	}
	if _, err := Verify(sign(t, priv, base()), want); err != nil {
		t.Fatal(err)
	}
	mutations := map[string]func(m map[string]any){
		"unknown field": func(m map[string]any) { m["shell"] = "id" },
		"version":       func(m map[string]any) { m["version"] = 2 },
		"marker":        func(m map[string]any) { m["marker"] = "DW-ffffffffffffffff" },
		"run id":        func(m map[string]any) { m["run_id"] = "../etc"; m["marker"] = "DW-../etc" },
		"no steps":      func(m map[string]any) { m["steps"] = []any{} },
		"hygiene in test": func(m map[string]any) {
			m["steps"] = []map[string]any{{"index": 0, "action": "hygiene.collect", "params": map[string]any{}}}
		},
		"bad kind": func(m map[string]any) { m["kind"] = "shell" },
		"unknown action": func(m map[string]any) {
			m["steps"] = []map[string]any{{"index": 0, "action": "shell.exec", "params": map[string]any{"cmd": "id"}}}
		},
		"order": func(m map[string]any) {
			m["steps"] = []map[string]any{{"index": 1, "action": "dns.sinkhole_query", "params": map[string]any{}}}
		},
		"bad time": func(m map[string]any) { m["expires_at"] = "tomorrow" },
	}
	for name, mutate := range mutations {
		p := base()
		mutate(p)
		if _, err := Verify(sign(t, priv, p), want); err == nil {
			t.Errorf("%s: accepted a bundle it should refuse", name)
		}
	}
}
