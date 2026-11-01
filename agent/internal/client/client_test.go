package client

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestClientAgainstTLSServer(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/enroll":
			var req EnrollRequest
			_ = json.NewDecoder(r.Body).Decode(&req)
			if req.Token != "good-token" {
				http.Error(w, `{"detail":"invalid token"}`, http.StatusForbidden)
				return
			}
			_ = json.NewEncoder(w).Encode(EnrollResponse{AgentID: "agt_1", HeartbeatInterval: 30, Tags: []string{"lab"}})
		case "/api/v1/agent/heartbeat":
			_ = json.NewEncoder(w).Encode(HeartbeatResponse{NextHeartbeat: 15})
		case "/api/v1/agent/tasks":
			_, _ = w.Write([]byte(`{"bundles":[{"payload":"cA==","signature":"cw==","key_id":"k"}]}`))
		case "/api/v1/agent/results":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{}`))
		}
	}))
	defer srv.Close()
	caFile := filepath.Join(t.TempDir(), "ca.crt")
	_ = os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600)
	c, err := New(srv.URL, caFile, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := c.Enroll(ctx, EnrollRequest{Token: "bad"}); err == nil {
		t.Fatal("bad token accepted")
	} else {
		var apiErr *APIError
		if !errors.As(err, &apiErr) || apiErr.Status != 403 {
			t.Errorf("want 403 APIError, got %v", err)
		}
	}
	resp, err := c.Enroll(ctx, EnrollRequest{Token: "good-token"})
	if err != nil || resp.AgentID != "agt_1" {
		t.Fatalf("enroll: %v", err)
	}
	hb, err := c.Heartbeat(ctx, map[string]any{"cpu_percent": 1}, "t")
	if err != nil || hb.NextHeartbeat != 15 {
		t.Fatalf("heartbeat: %v", err)
	}
	b, err := c.Tasks(ctx)
	if err != nil || len(b) != 1 || b[0].KeyID != "k" {
		t.Fatalf("tasks: %v", err)
	}
	if err := c.SubmitResults(ctx, Results{RunID: "x"}); err != nil {
		t.Fatal(err)
	}
	// A client that does not trust the server's certificate must refuse to talk to it.
	other := filepath.Join(t.TempDir(), "other.crt")
	_ = os.WriteFile(other, []byte("not a cert"), 0o600)
	if _, err := New(srv.URL, other, nil); err == nil {
		t.Error("accepted a CA file without certificates")
	}
}
