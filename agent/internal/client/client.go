// Package client talks to the Driftwatch server through the nginx mTLS proxy.
package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/blackdalc7/DriftWatch-Project/agent/internal/actions"
	"github.com/blackdalc7/DriftWatch-Project/agent/internal/bundle"
)

// Client is an HTTPS client that trusts only the Driftwatch CA.
type Client struct {
	base string
	http *http.Client
}

// APIError is a non-2xx response.
type APIError struct {
	Status int
	Body   string
}

func (e *APIError) Error() string { return fmt.Sprintf("server returned %d: %s", e.Status, e.Body) }

// New builds a client. cert may be nil for enrollment (the only endpoint that works without one).
func New(serverURL, caFile string, cert *tls.Certificate) (*Client, error) {
	pemBytes, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("cannot read CA file: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBytes) {
		return nil, fmt.Errorf("%s contains no PEM certificate", caFile)
	}
	tlsCfg := &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	if cert != nil {
		tlsCfg.Certificates = []tls.Certificate{*cert}
	}
	transport := &http.Transport{TLSClientConfig: tlsCfg, Proxy: http.ProxyFromEnvironment,
		IdleConnTimeout: 90 * time.Second, TLSHandshakeTimeout: 10 * time.Second}
	return NewWithHTTP(serverURL, &http.Client{Transport: transport, Timeout: 30 * time.Second}), nil
}

// NewWithHTTP wraps an existing http.Client (used by tests).
func NewWithHTTP(serverURL string, h *http.Client) *Client {
	return &Client{base: strings.TrimRight(serverURL, "/"), http: h}
}

func (c *Client) do(ctx context.Context, method, path string, body, out any) error {
	var reader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, reader)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "driftwatch-agent")
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode >= 300 {
		return &APIError{Status: resp.StatusCode, Body: strings.TrimSpace(string(data))}
	}
	if out != nil {
		return json.Unmarshal(data, out)
	}
	return nil
}

// EnrollRequest is sent once with the TTL token.
type EnrollRequest struct {
	Token        string `json:"token"`
	CSRPEM       string `json:"csr_pem"`
	Hostname     string `json:"hostname"`
	Platform     string `json:"platform"`
	OSVersion    string `json:"os_version"`
	AgentVersion string `json:"agent_version"`
}

// EnrollResponse carries the issued certificate.
type EnrollResponse struct {
	AgentID           string   `json:"agent_id"`
	CertificatePEM    string   `json:"certificate_pem"`
	CAPEM             string   `json:"ca_pem"`
	HeartbeatInterval int      `json:"heartbeat_interval"`
	Tags              []string `json:"tags"`
}

// Enroll exchanges a token and CSR for a client certificate.
func (c *Client) Enroll(ctx context.Context, r EnrollRequest) (*EnrollResponse, error) {
	var out EnrollResponse
	if err := c.do(ctx, http.MethodPost, "/api/v1/enroll", r, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// HeartbeatResponse tells the agent when to call again.
type HeartbeatResponse struct {
	ServerTime    string `json:"server_time"`
	NextHeartbeat int    `json:"next_heartbeat"`
	TasksPending  int    `json:"tasks_pending"`
}

// Heartbeat reports host metrics.
func (c *Client) Heartbeat(ctx context.Context, metrics map[string]any, version string) (*HeartbeatResponse, error) {
	var out HeartbeatResponse
	err := c.do(ctx, http.MethodPost, "/api/v1/agent/heartbeat",
		map[string]any{"metrics": metrics, "agent_version": version}, &out)
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// Tasks fetches signed bundles that are due.
func (c *Client) Tasks(ctx context.Context) ([]bundle.Signed, error) {
	var out struct {
		Bundles []bundle.Signed `json:"bundles"`
	}
	if err := c.do(ctx, http.MethodGet, "/api/v1/agent/tasks", nil, &out); err != nil {
		return nil, err
	}
	return out.Bundles, nil
}

// Results is the report for one run.
type Results struct {
	RunID      string           `json:"run_id"`
	StartedAt  string           `json:"started_at"`
	FinishedAt string           `json:"finished_at"`
	Steps      []actions.Result `json:"steps"`
	Log        string           `json:"log"`
}

// SubmitResults posts what the agent did.
func (c *Client) SubmitResults(ctx context.Context, r Results) error {
	return c.do(ctx, http.MethodPost, "/api/v1/agent/results", r, nil)
}
