package dispatch

import (
	"context"
	"net/http/httptest"
	"testing"

	"github.com/devSealWare/LightIPAM/internal/scanner"
	"github.com/devSealWare/LightIPAM/internal/scanner/agent"
	"github.com/devSealWare/LightIPAM/internal/scanner/pki"
)

func startAgent(t *testing.T) (string, *Dispatcher) {
	t.Helper()
	bundle, err := pki.Generate(pki.Options{})
	if err != nil {
		t.Fatalf("generate pki: %v", err)
	}
	serverCfg, err := agent.ServerTLSConfig(bundle.ServerCertPEM, bundle.ServerKeyPEM, bundle.CACertPEM)
	if err != nil {
		t.Fatalf("server tls: %v", err)
	}
	a := agent.New(agent.Config{
		Registration: scanner.AgentRegistration{
			ID:           "agent-1",
			Status:       scanner.AgentActive,
			AllowedCIDRs: []string{"192.168.0.0/16"},
		},
		ExpectedClientCN: pki.AppClientCN,
	})
	srv := httptest.NewUnstartedServer(a.Handler())
	srv.TLS = serverCfg
	srv.StartTLS()
	t.Cleanup(srv.Close)

	d, err := New(bundle.ClientCertPEM, bundle.ClientKeyPEM, bundle.CACertPEM)
	if err != nil {
		t.Fatalf("new dispatcher: %v", err)
	}
	return srv.URL, d
}

func job() scanner.ScanJob {
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

func TestDispatchValidJob(t *testing.T) {
	url, d := startAgent(t)
	result, err := d.Dispatch(context.Background(), url, job())
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if result.Status != scanner.JobSucceeded {
		t.Fatalf("expected succeeded, got %q", result.Status)
	}
}

func TestDispatchRejectedJob(t *testing.T) {
	url, d := startAgent(t)
	j := job()
	j.AllowedCIDRs = []string{"10.0.0.0/24"}
	j.Targets = []string{"10.0.0.5"}
	result, err := d.Dispatch(context.Background(), url, j)
	if err != nil {
		t.Fatalf("dispatch should not error on a rejected job: %v", err)
	}
	if result.Status != scanner.JobRejected {
		t.Fatalf("expected rejected, got %q", result.Status)
	}
}

func TestHealthCheck(t *testing.T) {
	url, d := startAgent(t)
	version, err := d.HealthCheck(context.Background(), url)
	if err != nil {
		t.Fatalf("health check: %v", err)
	}
	if version != scanner.ProtocolVersion {
		t.Fatalf("expected version %q, got %q", scanner.ProtocolVersion, version)
	}
}

func TestDispatchUnreachableAgent(t *testing.T) {
	_, d := startAgent(t)
	if _, err := d.Dispatch(context.Background(), "https://127.0.0.1:1", job()); err == nil {
		t.Fatal("expected error contacting unreachable agent")
	}
}
