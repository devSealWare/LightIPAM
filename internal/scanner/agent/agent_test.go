package agent

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/devSealWare/LightIPAM/internal/scanner"
	"github.com/devSealWare/LightIPAM/internal/scanner/pki"
)

func testRegistration() scanner.AgentRegistration {
	return scanner.AgentRegistration{
		ID:                 "agent-1",
		Name:               "test-agent",
		Status:             scanner.AgentActive,
		CertificateSubject: pki.AgentServerCN,
		AllowedCIDRs:       []string{"192.168.0.0/16"},
	}
}

func validJob() scanner.ScanJob {
	return scanner.ScanJob{
		ID:             "job-1",
		AgentID:        "agent-1",
		Type:           scanner.ScanHostDiscovery,
		Mode:           scanner.ModePassive,
		AllowedCIDRs:   []string{"192.168.10.0/24"},
		Targets:        []string{"192.168.10.20"},
		TimeoutSeconds: 60,
	}
}

// startMTLS spins up the agent over mTLS and returns a client that presents the
// app client certificate.
func startMTLS(t *testing.T) (*httptest.Server, *http.Client, *pki.Bundle) {
	t.Helper()
	bundle, err := pki.Generate(pki.Options{})
	if err != nil {
		t.Fatalf("generate pki: %v", err)
	}

	serverCfg, err := ServerTLSConfig(bundle.ServerCertPEM, bundle.ServerKeyPEM, bundle.CACertPEM)
	if err != nil {
		t.Fatalf("server tls config: %v", err)
	}

	a := New(Config{Registration: testRegistration(), ExpectedClientCN: pki.AppClientCN})
	srv := httptest.NewUnstartedServer(a.Handler())
	srv.TLS = serverCfg
	srv.StartTLS()
	t.Cleanup(srv.Close)

	clientCfg, err := ClientTLSConfig(bundle.ClientCertPEM, bundle.ClientKeyPEM, bundle.CACertPEM, pki.AgentServerCN)
	if err != nil {
		t.Fatalf("client tls config: %v", err)
	}
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: clientCfg}}
	return srv, client, bundle
}

func postJob(t *testing.T, client *http.Client, url string, job scanner.ScanJob) (*http.Response, scanner.ScanResult) {
	t.Helper()
	body, err := json.Marshal(job)
	if err != nil {
		t.Fatalf("marshal job: %v", err)
	}
	resp, err := client.Post(url+"/jobs", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("post job: %v", err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	var result scanner.ScanResult
	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusUnprocessableEntity {
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			t.Fatalf("decode result: %v", err)
		}
	}
	return resp, result
}

func TestAgentAcceptsValidJobOverMTLS(t *testing.T) {
	srv, client, _ := startMTLS(t)

	resp, result := postJob(t, client, srv.URL, validJob())
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	if result.Status != scanner.JobSucceeded {
		t.Fatalf("expected succeeded, got %q", result.Status)
	}
	if len(result.Observations) != 0 {
		t.Fatalf("no-op agent should report no observations, got %d", len(result.Observations))
	}
	if result.ProtocolVersion != scanner.ProtocolVersion {
		t.Fatalf("expected protocol version %q, got %q", scanner.ProtocolVersion, result.ProtocolVersion)
	}
}

func TestAgentRejectsJobOutsideAllowlist(t *testing.T) {
	srv, client, _ := startMTLS(t)

	job := validJob()
	job.AllowedCIDRs = []string{"10.0.0.0/24"}
	job.Targets = []string{"10.0.0.5"}

	resp, result := postJob(t, client, srv.URL, job)
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422, got %d", resp.StatusCode)
	}
	if result.Status != scanner.JobRejected {
		t.Fatalf("expected rejected, got %q", result.Status)
	}
	if len(result.Errors) == 0 {
		t.Fatal("expected rejection to include an error")
	}
}

func TestAgentHealthOverMTLS(t *testing.T) {
	srv, client, _ := startMTLS(t)

	resp, err := client.Get(srv.URL + "/healthz")
	if err != nil {
		t.Fatalf("get healthz: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	var body map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode health: %v", err)
	}
	if body["service"] != "light-ipam-scanner-agent" {
		t.Fatalf("unexpected service: %q", body["service"])
	}
}

func TestAgentRejectsConnectionWithoutClientCert(t *testing.T) {
	bundle, err := pki.Generate(pki.Options{})
	if err != nil {
		t.Fatalf("generate pki: %v", err)
	}
	serverCfg, err := ServerTLSConfig(bundle.ServerCertPEM, bundle.ServerKeyPEM, bundle.CACertPEM)
	if err != nil {
		t.Fatalf("server tls config: %v", err)
	}
	a := New(Config{Registration: testRegistration(), ExpectedClientCN: pki.AppClientCN})
	srv := httptest.NewUnstartedServer(a.Handler())
	srv.TLS = serverCfg
	srv.StartTLS()
	defer srv.Close()

	// Trust the server CA but present no client certificate.
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(bundle.CACertPEM)
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		RootCAs:    pool,
		ServerName: pki.AgentServerCN,
	}}}

	if _, err := client.Get(srv.URL + "/healthz"); err == nil {
		t.Fatal("expected handshake failure without client certificate")
	}
}

func TestVerifyClientCN(t *testing.T) {
	bundle, err := pki.Generate(pki.Options{})
	if err != nil {
		t.Fatalf("generate pki: %v", err)
	}
	a := New(Config{Registration: testRegistration(), ExpectedClientCN: pki.AppClientCN})

	req := httptest.NewRequest(http.MethodPost, "/jobs", nil)
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{parseCert(t, bundle.ClientCertPEM)}}
	if err := a.verifyClient(req); err != nil {
		t.Fatalf("expected app client cert to be accepted: %v", err)
	}

	// The agent's own server cert has a different CN and must be rejected.
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{parseCert(t, bundle.ServerCertPEM)}}
	if err := a.verifyClient(req); err == nil {
		t.Fatal("expected mismatched client CN to be rejected")
	}
}

func parseCert(t *testing.T, certPEM []byte) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatal("failed to decode PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return cert
}
