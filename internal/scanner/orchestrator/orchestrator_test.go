package orchestrator

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/devSealWare/LightIPAM/internal/scanner"
	"github.com/devSealWare/LightIPAM/internal/store"
)

type fakeDispatcher struct {
	enabled bool
	result  scanner.ScanResult
	err     error
}

func (f fakeDispatcher) Enabled() bool { return f.enabled }

func (f fakeDispatcher) Dispatch(_ context.Context, _ string, _ scanner.ScanJob) (scanner.ScanResult, error) {
	return f.result, f.err
}

func testService(d Dispatcher) *Service {
	return &Service{logger: slog.New(slog.NewTextHandler(io.Discard, nil)), dispatcher: d}
}

func sampleJob() store.ScanJob {
	return store.ScanJob{ID: "job-1", AgentID: "agent-1", ScanType: "host_discovery", Mode: "passive", TimeoutSeconds: 5}
}

func TestDispatchDisabled(t *testing.T) {
	s := testService(fakeDispatcher{enabled: false})
	out := s.dispatch(context.Background(), store.ScanAgent{ID: "agent-1"}, sampleJob(), time.Now())
	if out.Status != "failed" {
		t.Fatalf("expected failed, got %q", out.Status)
	}
	if !strings.Contains(out.Error, "not configured") {
		t.Fatalf("expected config error, got %q", out.Error)
	}
}

func TestDispatchTransportError(t *testing.T) {
	s := testService(fakeDispatcher{enabled: true, err: errors.New("connection refused")})
	out := s.dispatch(context.Background(), store.ScanAgent{ID: "agent-1"}, sampleJob(), time.Now())
	if out.Status != "failed" {
		t.Fatalf("expected failed, got %q", out.Status)
	}
	if out.Error != "connection refused" {
		t.Fatalf("expected transport error, got %q", out.Error)
	}
}

func TestDispatchSuccess(t *testing.T) {
	s := testService(fakeDispatcher{enabled: true, result: scanner.ScanResult{
		Status:       scanner.JobSucceeded,
		Observations: []scanner.Observation{},
	}})
	out := s.dispatch(context.Background(), store.ScanAgent{ID: "agent-1"}, sampleJob(), time.Now())
	if out.Status != "succeeded" {
		t.Fatalf("expected succeeded, got %q", out.Status)
	}
	if out.Result == "" {
		t.Fatal("expected the agent result to be serialized")
	}
	if out.Error != "" {
		t.Fatalf("did not expect an error, got %q", out.Error)
	}
}

func TestDispatchRejectedSurfacesError(t *testing.T) {
	s := testService(fakeDispatcher{enabled: true, result: scanner.ScanResult{
		Status: scanner.JobRejected,
		Errors: []scanner.ScanError{{Code: "job_rejected", Message: "outside the agent allowlist"}},
	}})
	out := s.dispatch(context.Background(), store.ScanAgent{ID: "agent-1"}, sampleJob(), time.Now())
	if out.Status != "rejected" {
		t.Fatalf("expected rejected, got %q", out.Status)
	}
	if out.Error != "outside the agent allowlist" {
		t.Fatalf("expected surfaced rejection error, got %q", out.Error)
	}
}

func TestRegistrationFromAgent(t *testing.T) {
	reg := registrationFromAgent(store.ScanAgent{ID: "a1", Status: "active", AllowedCIDRs: []string{"10.0.0.0/8"}})
	if reg.Status != scanner.AgentActive {
		t.Fatalf("expected active status, got %q", reg.Status)
	}
	if len(reg.AllowedCIDRs) != 1 {
		t.Fatalf("expected allowlist carried over")
	}
}
