// Package dispatch is the app-side mTLS client that sends scan jobs to a
// scanner agent and reads back the result. It is the counterpart to
// internal/scanner/agent. No scanning happens here; the agent owns that.
package dispatch

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"

	"github.com/devSealWare/LightIPAM/internal/scanner"
	"github.com/devSealWare/LightIPAM/internal/scanner/agent"
)

// Dispatcher posts scan jobs to agents over mTLS using the app's client
// certificate. A zero Dispatcher is not usable; build one with New.
type Dispatcher struct {
	client *http.Client
}

// New builds a Dispatcher from the app's client certificate material. The
// server name is verified per-request against the agent endpoint host, so the
// agent's certificate must carry that host as a SAN.
func New(clientCertPEM, clientKeyPEM, caPEM []byte) (*Dispatcher, error) {
	// Empty server name lets the HTTP client verify against each request's host.
	tlsConfig, err := agent.ClientTLSConfig(clientCertPEM, clientKeyPEM, caPEM, "")
	if err != nil {
		return nil, err
	}
	return &Dispatcher{
		client: &http.Client{
			Transport: &http.Transport{TLSClientConfig: tlsConfig},
		},
	}, nil
}

// Enabled reports whether dispatch is configured.
func (d *Dispatcher) Enabled() bool { return d != nil && d.client != nil }

// newAgentRequest builds an mTLS request to the agent at endpointURL+suffix. It
// re-validates the operator-supplied endpoint through scanner.ValidateAgentEndpoint
// before constructing the request, so the outbound connection cannot be pointed at
// a loopback/link-local/metadata target even if a malformed endpoint reached the
// store — defense in depth behind the app's save-time validation. Routing all four
// dispatcher methods through here keeps the client.Do sink sanitized in one place.
func newAgentRequest(ctx context.Context, method, endpointURL, suffix string, body io.Reader) (*http.Request, error) {
	normalized, err := scanner.ValidateAgentEndpoint(endpointURL)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(normalized, "/")+suffix, body)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	return req, nil
}

// Dispatch sends job to the agent's endpoint and returns the reported result.
// An error is returned for transport/TLS failures or non-JSON responses; an
// agent that rejects a job still returns a ScanResult (with a rejected status)
// and a nil error.
func (d *Dispatcher) Dispatch(ctx context.Context, endpointURL string, job scanner.ScanJob) (scanner.ScanResult, error) {
	if !d.Enabled() {
		return scanner.ScanResult{}, fmt.Errorf("dispatcher is not configured")
	}

	body, err := json.Marshal(job)
	if err != nil {
		return scanner.ScanResult{}, fmt.Errorf("marshal job: %w", err)
	}

	req, err := newAgentRequest(ctx, http.MethodPost, endpointURL, "/jobs", bytes.NewReader(body))
	if err != nil {
		return scanner.ScanResult{}, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := d.client.Do(req)
	if err != nil {
		return scanner.ScanResult{}, classifyDialError(err)
	}
	defer resp.Body.Close()

	payload, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return scanner.ScanResult{}, fmt.Errorf("read agent response: %w", err)
	}

	switch resp.StatusCode {
	case http.StatusOK, http.StatusUnprocessableEntity:
		var result scanner.ScanResult
		if err := json.Unmarshal(payload, &result); err != nil {
			return scanner.ScanResult{}, fmt.Errorf("decode agent result: %w", err)
		}
		return result, nil
	default:
		return scanner.ScanResult{}, fmt.Errorf("agent returned %d: %s", resp.StatusCode, strings.TrimSpace(string(payload)))
	}
}

// FetchRegistration pulls the agent's self-reported identity and allowlist from
// its /register endpoint over mTLS. It is the app side of auto-enrollment: the
// operator supplies only an endpoint URL and the app learns the rest.
func (d *Dispatcher) FetchRegistration(ctx context.Context, endpointURL string) (scanner.AgentRegistration, error) {
	if !d.Enabled() {
		return scanner.AgentRegistration{}, fmt.Errorf("dispatcher is not configured")
	}
	req, err := newAgentRequest(ctx, http.MethodGet, endpointURL, "/register", nil)
	if err != nil {
		return scanner.AgentRegistration{}, err
	}
	resp, err := d.client.Do(req)
	if err != nil {
		return scanner.AgentRegistration{}, classifyDialError(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return scanner.AgentRegistration{}, fmt.Errorf("agent register returned %d", resp.StatusCode)
	}
	var reg scanner.AgentRegistration
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&reg); err != nil {
		return scanner.AgentRegistration{}, fmt.Errorf("decode agent registration: %w", err)
	}
	return reg, nil
}

// HealthCheck contacts the agent's health endpoint and returns its reported
// version, confirming the mTLS path works end to end.
func (d *Dispatcher) HealthCheck(ctx context.Context, endpointURL string) (string, error) {
	if !d.Enabled() {
		return "", fmt.Errorf("dispatcher is not configured")
	}
	req, err := newAgentRequest(ctx, http.MethodGet, endpointURL, "/healthz", nil)
	if err != nil {
		return "", err
	}
	resp, err := d.client.Do(req)
	if err != nil {
		return "", classifyDialError(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("agent health returned %d", resp.StatusCode)
	}
	var body struct {
		ProtocolVersion string `json:"protocol_version"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&body); err != nil {
		return "", fmt.Errorf("decode agent health: %w", err)
	}
	return body.ProtocolVersion, nil
}

// Diagnostics fetches the agent's network self-view from its /diagnostics
// endpoint over mTLS, for the app's agent detail page. Read-only; the same mTLS
// client identity gates it as the other endpoints.
func (d *Dispatcher) Diagnostics(ctx context.Context, endpointURL string) (scanner.AgentDiagnostics, error) {
	if !d.Enabled() {
		return scanner.AgentDiagnostics{}, fmt.Errorf("dispatcher is not configured")
	}
	req, err := newAgentRequest(ctx, http.MethodGet, endpointURL, "/diagnostics", nil)
	if err != nil {
		return scanner.AgentDiagnostics{}, err
	}
	resp, err := d.client.Do(req)
	if err != nil {
		return scanner.AgentDiagnostics{}, classifyDialError(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return scanner.AgentDiagnostics{}, fmt.Errorf("agent diagnostics returned %d", resp.StatusCode)
	}
	var diag scanner.AgentDiagnostics
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&diag); err != nil {
		return scanner.AgentDiagnostics{}, fmt.Errorf("decode agent diagnostics: %w", err)
	}
	return diag, nil
}

// classifyDialError maps a transport error from contacting an agent to an
// actionable category, so an operator can tell the failure modes apart instead
// of reading one opaque "contact agent" wrapper:
//
//   - DNS (the agent name does not resolve): the scanner-agent container is not
//     running or not on the Compose network — the confusing "lookup scanner-agent
//     ... no such host" symptom from the field report.
//   - TLS / certificate: reached, but the mTLS handshake or cert validation failed.
//   - TCP (refused / unreachable / reset): resolved, but the port did not accept
//     the connection.
//
// The original error is always wrapped (%w) so the underlying detail is preserved
// for logs. errors.As walks the *url.Error the HTTP client returns, so the inner
// net/tls/x509 type is found regardless of wrapping. DNS is checked before the
// generic *net.OpError because a DNS failure is itself wrapped in an OpError.
func classifyDialError(err error) error {
	if err == nil {
		return nil
	}

	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return fmt.Errorf("scanner-agent is not resolvable (%q) — check the scanner-agent container is running "+
			"and attached to the Compose network (docker compose --profile scanner ps): %w", dnsErr.Name, err)
	}

	if isTLSError(err) {
		return fmt.Errorf("scanner-agent was reached, but mTLS/certificate validation failed — check the app and "+
			"agent share the managed CA and the certs are current: %w", err)
	}

	var opErr *net.OpError
	if errors.As(err, &opErr) {
		return fmt.Errorf("scanner-agent host resolved, but the connection failed — the agent's port may be "+
			"refused or unreachable (is the agent listening, and is a firewall in the way?): %w", err)
	}

	// Unknown transport error: keep the original wording so nothing is lost.
	return fmt.Errorf("contact agent: %w", err)
}

// isTLSError reports whether err is (or wraps) a TLS handshake or certificate
// validation failure.
func isTLSError(err error) bool {
	var (
		certVerify  *tls.CertificateVerificationError
		recordErr   tls.RecordHeaderError
		certInvalid x509.CertificateInvalidError
		unknownAuth x509.UnknownAuthorityError
		hostErr     x509.HostnameError
	)
	return errors.As(err, &certVerify) ||
		errors.As(err, &recordErr) ||
		errors.As(err, &certInvalid) ||
		errors.As(err, &unknownAuth) ||
		errors.As(err, &hostErr)
}
