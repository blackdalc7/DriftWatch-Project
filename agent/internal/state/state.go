// Package state persists the agent identity (id, key, certificate) and the run ids it has executed.
package state

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

const maxSeen = 1000

// Identity is what enrollment produced.
type Identity struct {
	AgentID           string   `json:"agent_id"`
	Hostname          string   `json:"hostname"`
	Tags              []string `json:"tags"`
	HeartbeatInterval int      `json:"heartbeat_interval"`
}

// Store reads and writes files in the state directory.
type Store struct {
	Dir string
	mu  sync.Mutex
}

func (s *Store) path(name string) string { return filepath.Join(s.Dir, name) }

// Enrolled reports whether an identity and certificate exist.
func (s *Store) Enrolled() bool {
	for _, f := range []string{"identity.json", "agent.key", "agent.crt"} {
		if _, err := os.Stat(s.path(f)); err != nil {
			return false
		}
	}
	return true
}

// NewKeyAndCSR creates a P-256 key (kept on disk, never sent) and a CSR for enrollment.
func (s *Store) NewKeyAndCSR(hostname string) (string, error) {
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return "", err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", err
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(s.path("agent.key.pending"), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		return "", err
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: hostname}, SignatureAlgorithm: x509.ECDSAWithSHA256}, key)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr})), nil
}

// SaveEnrollment stores the certificate and identity and activates the pending key.
func (s *Store) SaveEnrollment(id Identity, certPEM string) error {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil || block.Type != "CERTIFICATE" {
		return errors.New("server returned an invalid certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return err
	}
	if cert.Subject.CommonName != id.AgentID {
		return fmt.Errorf("certificate CN %q does not match agent id %q", cert.Subject.CommonName, id.AgentID)
	}
	if err := os.WriteFile(s.path("agent.crt"), []byte(certPEM), 0o600); err != nil {
		return err
	}
	if err := os.Rename(s.path("agent.key.pending"), s.path("agent.key")); err != nil {
		return err
	}
	data, _ := json.MarshalIndent(id, "", "  ")
	return os.WriteFile(s.path("identity.json"), data, 0o600)
}

// Identity loads the stored identity.
func (s *Store) Identity() (*Identity, error) {
	data, err := os.ReadFile(s.path("identity.json"))
	if err != nil {
		return nil, fmt.Errorf("agent is not enrolled: %w", err)
	}
	var id Identity
	if err := json.Unmarshal(data, &id); err != nil {
		return nil, err
	}
	return &id, nil
}

// Certificate loads the client key pair for mTLS.
func (s *Store) Certificate() (tls.Certificate, error) {
	return tls.LoadX509KeyPair(s.path("agent.crt"), s.path("agent.key"))
}

func (s *Store) seen() []string {
	var ids []string
	if data, err := os.ReadFile(s.path("seen.json")); err == nil {
		_ = json.Unmarshal(data, &ids)
	}
	return ids
}

// AlreadyRan reports whether a run id was executed before (replay protection).
func (s *Store) AlreadyRan(runID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, id := range s.seen() {
		if id == runID {
			return true
		}
	}
	return false
}

// MarkRan records a run id, keeping the most recent maxSeen.
func (s *Store) MarkRan(runID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	ids := append(s.seen(), runID)
	if len(ids) > maxSeen {
		ids = ids[len(ids)-maxSeen:]
	}
	data, _ := json.Marshal(ids)
	return os.WriteFile(s.path("seen.json"), data, 0o600)
}
