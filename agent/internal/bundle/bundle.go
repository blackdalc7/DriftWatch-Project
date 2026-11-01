// Package bundle verifies signed task bundles from the server.
//
// A bundle is {payload, signature, key_id}. payload is base64 of the canonical JSON the server signed, so
// the agent verifies the Ed25519 signature over exactly those bytes with the public key pinned in its
// config, and only then parses them. After the signature, every field is checked: version, kind, agent id,
// platform, lab scope, validity window, run id format, marker, and every step against the compiled-in
// catalog.
package bundle

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/driftwatch/agent/internal/catalog"
)

// Version is the only bundle format version this agent understands.
const Version = 1

// MaxSkew tolerates small clock differences between server and agent.
const MaxSkew = 5 * time.Minute

var runIDPattern = regexp.MustCompile(`^[a-f0-9]{16}$`)

// Signed is a bundle as it arrives over the wire.
type Signed struct {
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
	KeyID     string `json:"key_id"`
}

// RawStep is a step before validation.
type RawStep struct {
	Index  int                        `json:"index"`
	Action string                     `json:"action"`
	Params map[string]json.RawMessage `json:"params"`
}

// Payload is the signed content.
type Payload struct {
	Version     int       `json:"version"`
	Kind        string    `json:"kind"`
	RunID       string    `json:"run_id"`
	Marker      string    `json:"marker"`
	AgentID     string    `json:"agent_id"`
	Platform    string    `json:"platform"`
	Scope       string    `json:"scope"`
	TestID      string    `json:"test_id"`
	TestVersion int       `json:"test_version"`
	Steps       []RawStep `json:"steps"`
	IssuedAt    string    `json:"issued_at"`
	ExpiresAt   string    `json:"expires_at"`
}

// Step is a validated step ready to execute.
type Step struct {
	Index  int
	Action string
	Params map[string]any
}

// Task is a fully verified bundle.
type Task struct {
	Payload
	Validated []Step
}

// Expect is what the agent requires of every bundle.
type Expect struct {
	PublicKey ed25519.PublicKey
	AgentID   string
	Platform  string
	Scope     string
	Now       time.Time
}

// KeyID mirrors the server's key_id: first 16 hex chars of SHA-256 over the base64 public key.
func KeyID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256([]byte(base64.StdEncoding.EncodeToString(pub)))
	return hex.EncodeToString(sum[:])[:16]
}

func parseTime(s string) (time.Time, error) {
	return time.Parse(time.RFC3339Nano, s)
}

// Verify checks the signature and every field, returning the task or a reason to refuse it.
func Verify(b Signed, want Expect) (*Task, error) {
	if len(want.PublicKey) != ed25519.PublicKeySize {
		return nil, errors.New("no valid pinned signing key configured")
	}
	raw, err := base64.StdEncoding.DecodeString(b.Payload)
	if err != nil {
		return nil, fmt.Errorf("payload is not base64: %w", err)
	}
	sig, err := base64.StdEncoding.DecodeString(b.Signature)
	if err != nil {
		return nil, fmt.Errorf("signature is not base64: %w", err)
	}
	if !ed25519.Verify(want.PublicKey, raw, sig) {
		return nil, fmt.Errorf("bad signature (bundle key %s, pinned key %s)", b.KeyID, KeyID(want.PublicKey))
	}
	var p Payload
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("payload does not match the bundle format: %w", err)
	}
	if p.Version != Version {
		return nil, fmt.Errorf("unsupported bundle version %d", p.Version)
	}
	if !runIDPattern.MatchString(p.RunID) || p.Marker != "DW-"+p.RunID {
		return nil, errors.New("run id or marker is malformed")
	}
	if p.AgentID != want.AgentID {
		return nil, fmt.Errorf("bundle is for agent %s, not %s", p.AgentID, want.AgentID)
	}
	if p.Platform != want.Platform {
		return nil, fmt.Errorf("bundle is for platform %s, not %s", p.Platform, want.Platform)
	}
	if want.Scope == "" || p.Scope != want.Scope {
		return nil, fmt.Errorf("bundle scope %q does not match this agent's lab scope %q", p.Scope, want.Scope)
	}
	issued, err := parseTime(p.IssuedAt)
	if err != nil {
		return nil, fmt.Errorf("bad issued_at: %w", err)
	}
	expires, err := parseTime(p.ExpiresAt)
	if err != nil {
		return nil, fmt.Errorf("bad expires_at: %w", err)
	}
	if issued.After(want.Now.Add(MaxSkew)) {
		return nil, errors.New("bundle was issued in the future; check the clocks")
	}
	if !want.Now.Before(expires) {
		return nil, fmt.Errorf("bundle expired at %s", p.ExpiresAt)
	}
	if len(p.Steps) == 0 || len(p.Steps) > 20 {
		return nil, errors.New("bundle must have between 1 and 20 steps")
	}
	task := &Task{Payload: p}
	for i, s := range p.Steps {
		if s.Index != i {
			return nil, errors.New("steps are out of order")
		}
		isHygiene := s.Action == "hygiene.collect"
		if isHygiene != (p.Kind == "hygiene") || (p.Kind != "hygiene" && p.Kind != "test") {
			return nil, fmt.Errorf("action %s is not allowed in a %q bundle", s.Action, p.Kind)
		}
		params, err := catalog.Validate(s.Action, s.Params, want.Platform)
		if err != nil {
			return nil, fmt.Errorf("step %d refused: %w", i, err)
		}
		task.Validated = append(task.Validated, Step{Index: i, Action: s.Action, Params: params})
	}
	return task, nil
}
