// Package agent implements the Light IPAM scanner agent's receive/report side
// of the protocol defined in internal/scanner. At this stage the agent performs
// no active scanning: it authenticates the app over mTLS, validates submitted
// jobs against its registered allowlist, and reports an empty (no-op) result.
//
// Active discovery (Nmap, host probing) is intentionally not implemented here.
package agent

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/devSealWare/LightIPAM/internal/scanner"
)

// Config configures an agent instance.
type Config struct {
	// Registration is the agent's own identity and allowlist as registered
	// with the app. Submitted jobs are validated against it.
	Registration scanner.AgentRegistration
	// ExpectedClientCN, when set, requires the connecting app's client
	// certificate CommonName to match before a job is accepted. This is the
	// agent-side half of the mTLS identity check.
	ExpectedClientCN string
	Logger           *slog.Logger
}

// Agent serves the scanner protocol receive/report endpoints.
type Agent struct {
	cfg    Config
	logger *slog.Logger
}

// New returns an agent for the given config. A nil logger is replaced with a
// discarding logger.
func New(cfg Config) *Agent {
	logger := cfg.Logger
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return &Agent{cfg: cfg, logger: logger}
}

// Handler returns the agent's HTTP routes.
func (a *Agent) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", a.health)
	mux.HandleFunc("POST /jobs", a.submitJob)
	return mux
}

func (a *Agent) health(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{
		"status":           "ok",
		"service":          "light-ipam-scanner-agent",
		"protocol_version": scanner.ProtocolVersion,
		"agent_id":         a.cfg.Registration.ID,
	})
}

// submitJob receives a scan job from the app, verifies the client identity and
// allowlist, and reports a no-op result.
func (a *Agent) submitJob(w http.ResponseWriter, r *http.Request) {
	if err := a.verifyClient(r); err != nil {
		a.logger.Warn("rejected job: client identity", "error", err)
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}

	var job scanner.ScanJob
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&job); err != nil {
		http.Error(w, fmt.Sprintf("invalid scan job: %v", err), http.StatusBadRequest)
		return
	}

	result := a.processJob(job)
	status := http.StatusOK
	if result.Status == scanner.JobRejected {
		status = http.StatusUnprocessableEntity
		a.logger.Warn("rejected job", "job_id", job.ID, "errors", result.Errors)
	} else {
		a.logger.Info("processed no-op job", "job_id", job.ID, "observations", len(result.Observations))
	}
	writeJSON(w, status, result)
}

// processJob validates a job against the agent's registration and returns a
// result. With active scanning unimplemented, a valid job yields an empty
// successful result; an invalid one is rejected with the validation error.
func (a *Agent) processJob(job scanner.ScanJob) scanner.ScanResult {
	now := time.Now().UTC()
	result := scanner.ScanResult{
		ProtocolVersion: scanner.ProtocolVersion,
		JobID:           job.ID,
		AgentID:         a.cfg.Registration.ID,
		FinishedAt:      &now,
		Observations:    []scanner.Observation{},
		Errors:          []scanner.ScanError{},
	}

	if err := scanner.ValidateAgentScope(job, a.cfg.Registration.AllowedCIDRs); err != nil {
		result.Status = scanner.JobRejected
		result.Errors = append(result.Errors, scanner.ScanError{
			Code:    "job_rejected",
			Message: err.Error(),
		})
		return result
	}

	// No-op: the agent accepts the job but does not yet perform active scanning.
	result.Status = scanner.JobSucceeded
	result.StartedAt = &now
	return result
}

func (a *Agent) verifyClient(r *http.Request) error {
	if a.cfg.ExpectedClientCN == "" {
		return nil
	}
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return fmt.Errorf("client certificate required")
	}
	if cn := r.TLS.PeerCertificates[0].Subject.CommonName; cn != a.cfg.ExpectedClientCN {
		return fmt.Errorf("client identity %q is not authorized", cn)
	}
	return nil
}

// ServerTLSConfig builds a TLS config for the agent server that requires and
// verifies a client certificate chaining to the provided CA.
func ServerTLSConfig(certPEM, keyPEM, caPEM []byte) (*tls.Config, error) {
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("load server keypair: %w", err)
	}
	pool, err := certPool(caPEM)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientCAs:    pool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS12,
	}, nil
}

// ClientTLSConfig builds a TLS config for the app to connect to the agent,
// presenting its client certificate and verifying the agent against the CA.
func ClientTLSConfig(certPEM, keyPEM, caPEM []byte, serverName string) (*tls.Config, error) {
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("load client keypair: %w", err)
	}
	pool, err := certPool(caPEM)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      pool,
		ServerName:   serverName,
		MinVersion:   tls.VersionTLS12,
	}, nil
}

func certPool(caPEM []byte) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("no CA certificates found in PEM input")
	}
	return pool, nil
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
