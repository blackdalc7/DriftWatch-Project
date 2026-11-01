// Package agent is the main loop: heartbeat, fetch bundles, verify, execute, report.
package agent

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/blackdalc7/DriftWatch-Project/agent/internal/actions"
	"github.com/blackdalc7/DriftWatch-Project/agent/internal/bundle"
	"github.com/blackdalc7/DriftWatch-Project/agent/internal/client"
	"github.com/blackdalc7/DriftWatch-Project/agent/internal/state"
)

// API is the subset of the server client the loop needs (an interface so tests can fake it).
type API interface {
	Heartbeat(ctx context.Context, metrics map[string]any, version string) (*client.HeartbeatResponse, error)
	Tasks(ctx context.Context) ([]bundle.Signed, error)
	SubmitResults(ctx context.Context, r client.Results) error
}

// Agent holds everything one polling cycle needs.
type Agent struct {
	API       API
	State     *state.Store
	Identity  *state.Identity
	PublicKey ed25519.PublicKey
	Platform  string
	Scope     string
	Workspace string
	Version   string
	Metrics   func(ctx context.Context) map[string]any
	Hygiene   actions.HygieneFunc
	Log       *slog.Logger
	Now       func() time.Time
	Sleep     func(ctx context.Context, d time.Duration)
}

func timestamp(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05.000000Z") }

// Cycle runs one heartbeat and processes any bundles. It returns the next interval the server asked for.
func (a *Agent) Cycle(ctx context.Context) (int, error) {
	hb, err := a.API.Heartbeat(ctx, a.Metrics(ctx), a.Version)
	if err != nil {
		return 0, fmt.Errorf("heartbeat: %w", err)
	}
	bundles, err := a.API.Tasks(ctx)
	if err != nil {
		return hb.NextHeartbeat, fmt.Errorf("tasks: %w", err)
	}
	for _, b := range bundles {
		if ctx.Err() != nil {
			break
		}
		a.handle(ctx, b)
	}
	return hb.NextHeartbeat, nil
}

func (a *Agent) handle(ctx context.Context, b bundle.Signed) {
	task, err := bundle.Verify(b, bundle.Expect{PublicKey: a.PublicKey, AgentID: a.Identity.AgentID,
		Platform: a.Platform, Scope: a.Scope, Now: a.Now()})
	if err != nil {
		// Refused bundles are never executed. The server expires the run; nothing is reported because
		// an unverified run id cannot be trusted either.
		a.Log.Warn("refused bundle", "reason", err.Error(), "key_id", b.KeyID)
		return
	}
	if a.State.AlreadyRan(task.RunID) {
		a.Log.Warn("refused replayed bundle", "run_id", task.RunID)
		return
	}
	if err := a.State.MarkRan(task.RunID); err != nil {
		a.Log.Error("cannot record run id; refusing to execute", "run_id", task.RunID, "error", err)
		return
	}
	a.Log.Info("executing", "run_id", task.RunID, "test", task.TestID, "steps", len(task.Validated))
	runner := &actions.Runner{Workspace: a.Workspace, Marker: task.Marker, RunID: task.RunID,
		Platform: a.Platform, Hygiene: a.Hygiene, Sleep: a.Sleep}
	started := a.Now()
	var results []actions.Result
	var logLines []string
	for _, step := range task.Validated {
		res := runner.Run(ctx, step)
		results = append(results, res)
		logLines = append(logLines, fmt.Sprintf("%s step %d %s: %s (cleanup %s) %s", res.FinishedAt, res.Index,
			res.Action, res.Status, res.Cleanup, firstLine(res.Detail)))
	}
	report := client.Results{RunID: task.RunID, StartedAt: timestamp(started), FinishedAt: timestamp(a.Now()),
		Steps: results, Log: strings.Join(logLines, "\n")}
	for attempt := 1; attempt <= 5; attempt++ {
		if err = a.API.SubmitResults(ctx, report); err == nil {
			a.Log.Info("results submitted", "run_id", task.RunID)
			return
		}
		a.Log.Warn("submitting results failed", "run_id", task.RunID, "attempt", attempt, "error", err)
		a.Sleep(ctx, time.Duration(attempt*attempt)*time.Second)
	}
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

// Run loops until the context is cancelled, backing off on errors.
func (a *Agent) Run(ctx context.Context, interval func(server int) time.Duration) {
	backoff := time.Duration(0)
	for ctx.Err() == nil {
		next, err := a.Cycle(ctx)
		wait := interval(next)
		if err != nil {
			backoff = min(max(backoff*2, 5*time.Second), 5*time.Minute)
			wait = backoff
			a.Log.Warn("cycle failed", "error", err, "retry_in", wait.String())
		} else {
			backoff = 0
		}
		a.Sleep(ctx, wait)
	}
}
