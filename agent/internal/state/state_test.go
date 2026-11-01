package state

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// issue signs the pending CSR like the server's CA would (CN forced to the agent id).
func issue(t *testing.T, csrPEM, cn string) string {
	t.Helper()
	block, _ := pem.Decode([]byte(csrPEM))
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil || csr.CheckSignature() != nil {
		t.Fatalf("bad CSR: %v", err)
	}
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, csr.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func TestEnrollmentLifecycle(t *testing.T) {
	s := &Store{Dir: filepath.Join(t.TempDir(), "state")}
	if s.Enrolled() {
		t.Fatal("fresh store claims to be enrolled")
	}
	csr, err := s.NewKeyAndCSR("lab-lin01")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SaveEnrollment(Identity{AgentID: "agt_1"}, issue(t, csr, "agt_other")); err == nil {
		t.Fatal("accepted a certificate for another agent")
	}
	if err := s.SaveEnrollment(Identity{AgentID: "agt_1", Tags: []string{"lab"}}, issue(t, csr, "agt_1")); err != nil {
		t.Fatal(err)
	}
	if !s.Enrolled() {
		t.Fatal("not enrolled after saving")
	}
	if _, err := s.Certificate(); err != nil {
		t.Fatalf("key pair does not load: %v", err)
	}
	id, _ := s.Identity()
	if id.AgentID != "agt_1" || id.Tags[0] != "lab" {
		t.Errorf("identity %+v", id)
	}
	info, _ := os.Stat(filepath.Join(s.Dir, "agent.key"))
	if info.Mode().Perm()&0o077 != 0 {
		t.Errorf("private key is readable by others: %v", info.Mode())
	}
	if err := s.SaveEnrollment(Identity{AgentID: "x"}, "not pem"); err == nil {
		t.Error("accepted garbage certificate")
	}
}

func TestReplayList(t *testing.T) {
	s := &Store{Dir: t.TempDir()}
	if s.AlreadyRan("a") {
		t.Fatal("empty list")
	}
	for i := 0; i < maxSeen+5; i++ {
		_ = s.MarkRan(string(rune('a'+i%26)) + time.Now().Format("150405.000000000"))
	}
	_ = s.MarkRan("last")
	if !s.AlreadyRan("last") || len(s.seen()) != maxSeen {
		t.Errorf("seen list size %d", len(s.seen()))
	}
}
