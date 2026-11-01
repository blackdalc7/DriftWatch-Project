package agent

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/blackdalc7/DriftWatch-Project/agent/internal/bundle"
	"github.com/blackdalc7/DriftWatch-Project/agent/internal/client"
	"github.com/blackdalc7/DriftWatch-Project/agent/internal/state"
)

type fakeAPI struct {
	bundles    []bundle.Signed
	submitted  []client.Results
	failSubmit int
	hbErr      error
}

func (f *fakeAPI) Heartbeat(context.Context, map[string]any, string) (*client.HeartbeatResponse, error) {
	if f.hbErr != nil {
		return nil, f.hbErr
	}
	return &client.HeartbeatResponse{NextHeartbeat: 30}, nil
}

func (f *fakeAPI) Tasks(context.Context) ([]bundle.Signed, error) {
	b := f.bundles
	f.bundles = nil
	return b, nil
}

func (f *fakeAPI) SubmitResults(_ context.Context, r client.Results) error {
	if f.failSubmit > 0 {
		f.failSubmit--
		return errors.New("server down")
	}
	f.submitted = append(f.submitted, r)
	return nil
}

func signed(priv ed25519.PrivateKey, runID, action string, params map[string]any) bundle.Signed {
	payload := map[string]any{"version": 1, "kind": "test", "run_id": runID, "marker": "DW-" + runID,
		"agent_id": "agt_1", "platform": "linux", "scope": "lab", "test_id": "dw-x", "test_version": 1,
		"issued_at": "2026-10-30T13:59:00Z", "expires_at": "2026-10-30T14:10:00Z",
		"steps": []map[string]any{{"index": 0, "action": action, "params": params}}}
	raw, _ := json.Marshal(payload)
	return bundle.Signed{Payload: base64.StdEncoding.EncodeToString(raw),
		Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(priv, raw))}
}

func newAgent(t *testing.T, api *fakeAPI, pub ed25519.PublicKey) *Agent {
	return &Agent{API: api, State: &state.Store{Dir: t.TempDir()}, Identity: &state.Identity{AgentID: "agt_1"},
		PublicKey: pub, Platform: "linux", Scope: "lab", Workspace: t.TempDir(), Version: "test",
		Metrics: func(context.Context) map[string]any { return map[string]any{"cpu_percent": 1.0} },
		Log:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		Now:     func() time.Time { return time.Date(2026, 10, 30, 14, 0, 0, 0, time.UTC) },
		Sleep:   func(context.Context, time.Duration) {}}
}

func TestCycleExecutesVerifiedBundlesOnce(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	_, evil, _ := ed25519.GenerateKey(rand.Reader)
	good := signed(priv, "0123456789abcdef", "dns.sinkhole_query", map[string]any{"count": 1})
	api := &fakeAPI{failSubmit: 2, bundles: []bundle.Signed{
		good,
		signed(evil, "1111111111111111", "dns.sinkhole_query", map[string]any{}),    // wrong key
		signed(priv, "2222222222222222", "shell.exec", map[string]any{"cmd": "id"}), // not in catalog
	}}
	a := newAgent(t, api, pub)
	next, err := a.Cycle(context.Background())
	if err != nil || next != 30 {
		t.Fatalf("cycle: %v %d", err, next)
	}
	if len(api.submitted) != 1 || api.submitted[0].RunID != "0123456789abcdef" {
		t.Fatalf("expected exactly the verified run to be reported, got %+v", api.submitted)
	}
	if api.submitted[0].Steps[0].Status != "executed" {
		t.Errorf("step: %+v", api.submitted[0].Steps[0])
	}
	api.bundles = []bundle.Signed{good} // replay
	if _, err := a.Cycle(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(api.submitted) != 1 {
		t.Error("a replayed bundle was executed again")
	}
}

func TestRunBacksOffOnErrors(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	api := &fakeAPI{hbErr: errors.New("connection refused")}
	a := newAgent(t, api, pub)
	ctx, cancel := context.WithCancel(context.Background())
	var waits []time.Duration
	a.Sleep = func(_ context.Context, d time.Duration) {
		waits = append(waits, d)
		if len(waits) == 4 {
			cancel()
		}
	}
	a.Run(ctx, func(int) time.Duration { return time.Second })
	if waits[0] != 5*time.Second || waits[1] != 10*time.Second || waits[3] != 40*time.Second {
		t.Errorf("unexpected backoff %v", waits)
	}
}
