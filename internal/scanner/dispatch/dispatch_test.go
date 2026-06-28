package dispatch

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"syscall"
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

func TestDiagnostics(t *testing.T) {
	url, d := startAgent(t)
	diag, err := d.Diagnostics(context.Background(), url)
	if err != nil {
		t.Fatalf("diagnostics: %v", err)
	}
	if diag.AgentID != "agent-1" {
		t.Fatalf("expected agent-1, got %q", diag.AgentID)
	}
	// No egress configured on the test agent, so the pin mode is the default.
	if diag.PinMode != "auto" {
		t.Fatalf("expected default pin mode auto, got %q", diag.PinMode)
	}
}

func TestDispatchUnreachableAgent(t *testing.T) {
	_, d := startAgent(t)
	_, err := d.Dispatch(context.Background(), "https://127.0.0.1:1", job())
	if err == nil {
		t.Fatal("expected error contacting unreachable agent")
	}
	// The refused connection is classified as a TCP failure, not an opaque wrap.
	if !strings.Contains(err.Error(), "connection failed") {
		t.Fatalf("expected a classified TCP failure, got %q", err)
	}
}

func TestClassifyDialError(t *testing.T) {
	// Mirror how the HTTP client wraps transport errors: in a *url.Error.
	wrap := func(e error) error {
		return &url.Error{Op: "Post", URL: "https://scanner-agent:8443/jobs", Err: e}
	}

	dns := wrap(&net.OpError{Op: "dial", Net: "tcp", Err: &net.DNSError{Name: "scanner-agent", IsNotFound: true}})
	tcp := wrap(&net.OpError{Op: "dial", Net: "tcp", Err: &os.SyscallError{Syscall: "connect", Err: syscall.ECONNREFUSED}})
	tlsErr := wrap(&tls.CertificateVerificationError{Err: x509.UnknownAuthorityError{}})

	cases := []struct {
		name string
		err  error
		want string
	}{
		{"dns", dns, "not resolvable"},
		{"tcp", tcp, "connection failed"},
		{"tls", tlsErr, "mTLS/certificate"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := classifyDialError(tc.err)
			if got == nil {
				t.Fatalf("classifyDialError returned nil for %v", tc.err)
			}
			if !strings.Contains(got.Error(), tc.want) {
				t.Fatalf("classifyDialError(%s) = %q, want substring %q", tc.name, got, tc.want)
			}
			// The original transport error must remain unwrappable for logs.
			if !errors.Is(got, tc.err) {
				t.Fatalf("%s: classified error dropped the original (errors.Is failed)", tc.name)
			}
		})
	}

	// DNS must win over the generic *net.OpError it is wrapped in.
	var opErr *net.OpError
	if errors.As(dns, &opErr) {
		if got := classifyDialError(dns); !strings.Contains(got.Error(), "not resolvable") {
			t.Fatalf("DNS error must classify as unresolvable even though it is an OpError, got %q", got)
		}
	}

	// An unknown error keeps the original wording rather than mislabeling it.
	if got := classifyDialError(errors.New("weird")); !strings.Contains(got.Error(), "contact agent") {
		t.Fatalf("unknown error should fall back to the generic wrapper, got %q", got)
	}
	if classifyDialError(nil) != nil {
		t.Fatal("classifyDialError(nil) should be nil")
	}
}
