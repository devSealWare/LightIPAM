package agent

import (
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/devSealWare/LightIPAM/internal/scanner/pki"
)

func writeLeaf(t *testing.T, dir, base string, ca *pki.CA) (certPath, keyPath string) {
	t.Helper()
	certPEM, keyPEM, err := ca.IssueServer("agent", []string{"localhost"}, []net.IP{net.IPv4(127, 0, 0, 1)}, time.Hour)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	certPath = filepath.Join(dir, base+".crt")
	keyPath = filepath.Join(dir, base+".key")
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}

func TestCertReloaderReloadsOnChange(t *testing.T) {
	dir := t.TempDir()
	ca, _ := pki.NewCA(0)
	certPath, keyPath := writeLeaf(t, dir, "agent", ca)

	reloader, err := NewCertReloader(certPath, keyPath, nil)
	if err != nil {
		t.Fatalf("NewCertReloader: %v", err)
	}
	first, _ := reloader.GetCertificate(nil)
	if first == nil {
		t.Fatal("expected an initial certificate")
	}
	if reloader.changed() {
		t.Fatal("freshly loaded reloader should not report changed")
	}

	// Rotate: write a new keypair with a newer mod time.
	time.Sleep(10 * time.Millisecond)
	newCertPEM, newKeyPEM, _ := ca.IssueServer("agent", []string{"localhost"}, []net.IP{net.IPv4(127, 0, 0, 1)}, 2*time.Hour)
	future := time.Now().Add(time.Second)
	os.WriteFile(certPath, newCertPEM, 0o600)
	os.WriteFile(keyPath, newKeyPEM, 0o600)
	os.Chtimes(certPath, future, future)
	os.Chtimes(keyPath, future, future)

	if !reloader.changed() {
		t.Fatal("reloader should detect changed files")
	}
	if err := reloader.reload(); err != nil {
		t.Fatalf("reload: %v", err)
	}
	second, _ := reloader.GetCertificate(nil)
	if second == first {
		t.Error("certificate should have been swapped after reload")
	}
	if reloader.changed() {
		t.Error("after reload, changed() should be false again")
	}
}

func TestServerTLSConfigReloading(t *testing.T) {
	dir := t.TempDir()
	ca, _ := pki.NewCA(0)
	certPath, keyPath := writeLeaf(t, dir, "agent", ca)
	reloader, err := NewCertReloader(certPath, keyPath, nil)
	if err != nil {
		t.Fatalf("NewCertReloader: %v", err)
	}
	cfg, err := ServerTLSConfigReloading(reloader, ca.CertPEM())
	if err != nil {
		t.Fatalf("ServerTLSConfigReloading: %v", err)
	}
	if cfg.GetCertificate == nil {
		t.Error("config should use GetCertificate for hot reload")
	}
	if cfg.ClientCAs == nil {
		t.Error("config should require client CA")
	}
}
