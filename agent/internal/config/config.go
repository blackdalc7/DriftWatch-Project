// Package config loads the agent configuration file.
package config

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

// Config is the agent's JSON configuration.
type Config struct {
	// ServerURL is the nginx mTLS front door, e.g. https://driftwatch.lab:8443.
	ServerURL string `json:"server_url"`
	// CAFile is the Driftwatch internal CA certificate (deploy/pki/ca.crt).
	CAFile string `json:"ca_file"`
	// SigningPublicKey is the base64 Ed25519 key printed by `driftwatch pki init`. Bundles signed by any
	// other key are refused.
	SigningPublicKey string `json:"signing_public_key"`
	// LabScope must equal the scope in every bundle (the server's lab tag, normally "lab").
	LabScope string `json:"lab_scope"`
	// StateDir holds the agent key, certificate and identity.
	StateDir string `json:"state_dir"`
	// Workspace is where actions create (and remove) their canary artefacts.
	Workspace string `json:"workspace"`
	// PollSeconds overrides the server's heartbeat interval if set (minimum 5).
	PollSeconds int `json:"poll_seconds,omitempty"`
}

// Platform is this agent's platform name as the server knows it.
func Platform() string {
	if runtime.GOOS == "windows" {
		return "windows"
	}
	return "linux"
}

// Defaults returns per-platform default paths.
func Defaults() Config {
	if Platform() == "windows" {
		return Config{LabScope: "lab", StateDir: `C:\ProgramData\Driftwatch\state`,
			Workspace: `C:\ProgramData\Driftwatch\workspace`}
	}
	return Config{LabScope: "lab", StateDir: "/var/lib/driftwatch", Workspace: "/var/lib/driftwatch/workspace"}
}

// Load reads and validates a configuration file, filling defaults.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("cannot read config: %w", err)
	}
	cfg := Defaults()
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("invalid config JSON: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if !filepath.IsAbs(cfg.CAFile) {
		cfg.CAFile = filepath.Join(filepath.Dir(path), cfg.CAFile)
	}
	return &cfg, nil
}

// Validate checks required fields.
func (c *Config) Validate() error {
	u, err := url.Parse(c.ServerURL)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return errors.New("server_url must be an https URL")
	}
	if c.CAFile == "" {
		return errors.New("ca_file is required")
	}
	if _, err := c.PublicKey(); err != nil {
		return err
	}
	if c.LabScope == "" {
		return errors.New("lab_scope is required")
	}
	if c.StateDir == "" || c.Workspace == "" {
		return errors.New("state_dir and workspace are required")
	}
	if c.PollSeconds != 0 && c.PollSeconds < 5 {
		return errors.New("poll_seconds must be at least 5")
	}
	return nil
}

// PublicKey decodes the pinned bundle signing key.
func (c *Config) PublicKey() (ed25519.PublicKey, error) {
	raw, err := base64.StdEncoding.DecodeString(c.SigningPublicKey)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, errors.New("signing_public_key must be a base64 Ed25519 public key (32 bytes)")
	}
	return ed25519.PublicKey(raw), nil
}

// Poll returns the polling interval, preferring the config override.
func (c *Config) Poll(server int) time.Duration {
	if c.PollSeconds > 0 {
		return time.Duration(c.PollSeconds) * time.Second
	}
	if server < 5 {
		server = 30
	}
	return time.Duration(server) * time.Second
}
