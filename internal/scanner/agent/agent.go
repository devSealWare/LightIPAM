// Package agent implements the Light IPAM scanner agent's receive/report side
// of the protocol defined in internal/scanner. At this stage the agent performs
// no active scanning: it authenticates the app over mTLS, validates submitted
// jobs against its registered allowlist, and reports an empty (no-op) result.
//
// Active discovery (Nmap, host probing) is intentionally not implemented here.
package agent

import (
	"context"
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
	// Discoverer performs active scanning for non-passive jobs. When nil, the
	// agent stays a no-op (validates and accepts jobs but reports no
	// observations), preserving the pre-discovery behavior for tests.
	Discoverer Discoverer
	Logger     *slog.Logger
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
	mux.HandleFunc("GET /register", a.register)
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

// register returns the agent's self-reported identity and allowlist so the app
// can enroll it without an operator retyping every field. The connecting app is
// still authenticated by mTLS (and the optional client-CN check), so this
// exposes nothing an authorized app could not already learn.
func (a *Agent) register(w http.ResponseWriter, r *http.Request) {
	if err := a.verifyClient(r); err != nil {
		a.logger.Warn("rejected register: client identity", "error", err)
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	reg := a.cfg.Registration
	reg.Version = scanner.ProtocolVersion
	writeJSON(w, http.StatusOK, reg)
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

	result := a.processJob(r.Context(), job)
	status := http.StatusOK
	switch result.Status {
	case scanner.JobRejected:
		status = http.StatusUnprocessableEntity
		a.logger.Warn("rejected job", "job_id", job.ID, "errors", result.Errors)
	case scanner.JobFailed:
		a.logger.Warn("scan job failed", "job_id", job.ID, "errors", result.Errors)
	default:
		a.logger.Info("processed scan job", "job_id", job.ID, "mode", job.Mode, "observations", len(result.Observations))
	}
	writeJSON(w, status, result)
}

// processJob validates a job against the agent's registration and, for active
// modes, runs the configured discoverer. A passive job (or an agent with no
// discoverer configured) yields an empty successful result; an out-of-scope job
// is rejected; a discovery error is reported as a failed result.
func (a *Agent) processJob(ctx context.Context, job scanner.ScanJob) scanner.ScanResult {
	started := time.Now().UTC()
	result := scanner.ScanResult{
		ProtocolVersion: scanner.ProtocolVersion,
		JobID:           job.ID,
		AgentID:         a.cfg.Registration.ID,
		StartedAt:       &started,
		Observations:    []scanner.Observation{},
		Errors:          []scanner.ScanError{},
	}
	finish := func() { now := time.Now().UTC(); result.FinishedAt = &now }

	if err := scanner.ValidateAgentScope(job, a.cfg.Registration.AllowedCIDRs); err != nil {
		result.Status = scanner.JobRejected
		result.Errors = append(result.Errors, scanner.ScanError{Code: "job_rejected", Message: err.Error()})
		finish()
		return result
	}

	if a.cfg.Discoverer != nil && job.Mode != scanner.ModePassive {
		scanCtx := ctx
		if job.TimeoutSeconds > 0 {
			var cancel context.CancelFunc
			scanCtx, cancel = context.WithTimeout(ctx, time.Duration(job.TimeoutSeconds)*time.Second)
			defer cancel()
		}
		observations, scanErrs, err := a.cfg.Discoverer.Discover(scanCtx, job)
		if err != nil {
			result.Status = scanner.JobFailed
			result.Errors = append(result.Errors, scanner.ScanError{Code: "scan_failed", Message: err.Error()})
			finish()
			return result
		}
		if observations != nil {
			result.Observations = observations
		}
		if len(scanErrs) > 0 {
			result.Errors = scanErrs
		}
		result.Status = scanner.JobSucceeded
		finish()
		return result
	}

	// Passive mode, or no discoverer configured: accept without active probing.
	result.Status = scanner.JobSucceeded
	finish()
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
