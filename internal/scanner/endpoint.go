package scanner

import (
	"fmt"
	"net"
	"net/url"
	"strings"
)

// ValidateAgentEndpoint validates and normalizes an operator-supplied scanner-agent
// endpoint URL before the app stores it or the dispatcher connects to it. It is the
// SSRF guard for the dispatcher, whose methods perform a TCP connect + TLS
// ClientHello (an internal port-scan / metadata oracle) before the pinned-CA
// certificate check completes.
//
// The rules are deliberately narrow so legitimate agents keep working: agents live
// on private LANs, so private RFC-1918 ranges stay allowed. Only clearly-invalid
// agent locations are rejected — a non-https scheme, a missing host, or a literal
// loopback / link-local / unspecified IP (e.g. 127.0.0.1, 169.254.169.254, ::1,
// 0.0.0.0). Hostnames are not resolved here (that would make the check impure and
// depend on live DNS); the literal-IP rejection plus mTLS pinning is the guard.
func ValidateAgentEndpoint(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", fmt.Errorf("Enter an https:// endpoint URL for the agent.")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("Endpoint URL %q is not valid — use an https:// address like https://scanner-agent:8443.", raw)
	}
	if u.Scheme != "https" {
		return "", fmt.Errorf("Endpoint URL must use https://.")
	}
	host := u.Hostname()
	if host == "" {
		return "", fmt.Errorf("Endpoint URL must include a host.")
	}
	if ip := net.ParseIP(host); ip != nil {
		if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
			return "", fmt.Errorf("Endpoint URL %q points at a loopback or link-local address, which is not a valid agent location.", host)
		}
	}
	return u.String(), nil
}
