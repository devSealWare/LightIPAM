// Package dispatch is the app-side mTLS client that sends scan jobs to a
// scanner agent and reads back the result. It is the counterpart to
// internal/scanner/agent. No scanning happens here; the agent owns that.
package dispatch

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
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

	url := strings.TrimRight(endpointURL, "/") + "/jobs"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return scanner.ScanResult{}, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := d.client.Do(req)
	if err != nil {
		return scanner.ScanResult{}, fmt.Errorf("contact agent: %w", err)
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
	url := strings.TrimRight(endpointURL, "/") + "/register"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return scanner.AgentRegistration{}, fmt.Errorf("build request: %w", err)
	}
	resp, err := d.client.Do(req)
	if err != nil {
		return scanner.AgentRegistration{}, fmt.Errorf("contact agent: %w", err)
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
	url := strings.TrimRight(endpointURL, "/") + "/healthz"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", fmt.Errorf("build request: %w", err)
	}
	resp, err := d.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("contact agent: %w", err)
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
