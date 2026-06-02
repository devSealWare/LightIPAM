package pki

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

func TestGenerateProducesChainedCerts(t *testing.T) {
	bundle, err := Generate(Options{})
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(bundle.CACertPEM) {
		t.Fatal("ca cert not appended")
	}

	server := parse(t, bundle.ServerCertPEM)
	if _, err := server.Verify(x509.VerifyOptions{Roots: caPool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		t.Fatalf("server cert does not chain to CA: %v", err)
	}
	if server.Subject.CommonName != AgentServerCN {
		t.Fatalf("server CN = %q, want %q", server.Subject.CommonName, AgentServerCN)
	}

	client := parse(t, bundle.ClientCertPEM)
	if _, err := client.Verify(x509.VerifyOptions{Roots: caPool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Fatalf("client cert does not chain to CA: %v", err)
	}
	if client.Subject.CommonName != AppClientCN {
		t.Fatalf("client CN = %q, want %q", client.Subject.CommonName, AppClientCN)
	}
}

func TestWriteDir(t *testing.T) {
	bundle, err := Generate(Options{})
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	dir := t.TempDir()
	if err := bundle.WriteDir(dir); err != nil {
		t.Fatalf("write dir: %v", err)
	}
	for _, name := range []string{"ca.crt", "ca.key", "agent.crt", "agent.key", "app.crt", "app.key"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Fatalf("expected %s: %v", name, err)
		}
	}
	info, err := os.Stat(filepath.Join(dir, "agent.key"))
	if err != nil {
		t.Fatalf("stat agent.key: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("agent.key perm = %o, want 600", perm)
	}
}

func parse(t *testing.T, certPEM []byte) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatal("decode PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return cert
}
