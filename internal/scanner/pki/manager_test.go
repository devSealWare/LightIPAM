package pki

import (
	"crypto/x509"
	"encoding/pem"
	"net"
	"testing"
	"time"
)

func TestCAIssueAndVerify(t *testing.T) {
	ca, err := NewCA(0)
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}
	serverPEM, _, err := ca.IssueServer("agent-x", []string{"scanner-agent"}, []net.IP{net.IPv4(127, 0, 0, 1)}, time.Hour)
	if err != nil {
		t.Fatalf("IssueServer: %v", err)
	}
	clientPEM, _, err := ca.IssueClient("light-ipam-app", time.Hour)
	if err != nil {
		t.Fatalf("IssueClient: %v", err)
	}

	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca.CertPEM()) {
		t.Fatal("append CA cert")
	}
	// Server cert must verify for server auth against the CA.
	verifyLeaf(t, serverPEM, roots, x509.ExtKeyUsageServerAuth)
	verifyLeaf(t, clientPEM, roots, x509.ExtKeyUsageClientAuth)
}

func TestLoadCAStableRotation(t *testing.T) {
	ca, _ := NewCA(0)
	keyPEM, err := ca.KeyPEM()
	if err != nil {
		t.Fatalf("KeyPEM: %v", err)
	}
	// Reload the CA and issue a new leaf — it must still chain to the same root.
	reloaded, err := LoadCA(ca.CertPEM(), keyPEM)
	if err != nil {
		t.Fatalf("LoadCA: %v", err)
	}
	if reloaded.Fingerprint() != ca.Fingerprint() {
		t.Fatal("reloaded CA fingerprint changed")
	}
	leafPEM, _, err := reloaded.IssueServer("agent-y", []string{"scanner-agent"}, nil, time.Hour)
	if err != nil {
		t.Fatalf("IssueServer after reload: %v", err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(ca.CertPEM())
	verifyLeaf(t, leafPEM, roots, x509.ExtKeyUsageServerAuth)
}

func TestNeedsRenewal(t *testing.T) {
	ca, _ := NewCA(0)
	leafPEM, _, _ := ca.IssueServer("agent-z", nil, nil, time.Hour)
	now := time.Now()
	// Far from expiry with a small window: no renewal.
	if need, _ := NeedsRenewal(leafPEM, time.Minute, now); need {
		t.Error("should not need renewal an hour out with a 1m window")
	}
	// Large window catches it.
	if need, _ := NeedsRenewal(leafPEM, 2*time.Hour, now); !need {
		t.Error("should need renewal when the window exceeds remaining life")
	}
}

func TestFingerprintFormat(t *testing.T) {
	ca, _ := NewCA(0)
	fp, err := Fingerprint(ca.CertPEM())
	if err != nil {
		t.Fatalf("Fingerprint: %v", err)
	}
	// SHA-256 hex with colons => 32 bytes -> 64 hex chars + 31 colons = 95.
	if len(fp) != 95 {
		t.Errorf("fingerprint length = %d, want 95 (%q)", len(fp), fp)
	}
}

func verifyLeaf(t *testing.T, certPEM []byte, roots *x509.CertPool, usage x509.ExtKeyUsage) {
	t.Helper()
	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatal("decode leaf PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	if _, err := cert.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{usage}}); err != nil {
		t.Fatalf("verify leaf: %v", err)
	}
}
