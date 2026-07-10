package webhook

import (
	"fmt"
	"net"
	"net/url"
	"strings"
)

// ValidateURL validates and normalizes an admin-supplied webhook Payload URL
// before the app stores it or the dispatcher POSTs to it. It is the SSRF guard
// for the webhook path, mirroring scanner.ValidateAgentEndpoint's rules: only
// https:// is allowed (the payload carries an HMAC signature, but plaintext HTTP
// still leaks its content and is a downgrade vector), and a literal loopback,
// link-local, or unspecified IP (e.g. 127.0.0.1, 169.254.169.254, ::1, 0.0.0.0)
// is rejected — otherwise an admin (or an attacker who compromises an admin
// session) could point a webhook at cloud instance metadata or another
// internal-only service and have LightIPAM deliver a signed POST there on every
// matching audit event.
//
// Like the agent-endpoint guard, this deliberately does not resolve hostnames
// (that would make the check impure and depend on live DNS) and does not reject
// private RFC-1918 ranges (an admin may legitimately want to notify an internal
// service) — literal-IP rejection is the guard, not a substitute for admins
// trusting the webhook receivers they configure.
func ValidateURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", fmt.Errorf("Enter an https:// URL for the webhook.")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("Webhook URL %q is not valid — use an https:// address.", raw)
	}
	if u.Scheme != "https" {
		return "", fmt.Errorf("Webhook URL must use https://.")
	}
	host := u.Hostname()
	if host == "" {
		return "", fmt.Errorf("Webhook URL must include a host.")
	}
	if ip := net.ParseIP(host); ip != nil {
		if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
			return "", fmt.Errorf("Webhook URL %q points at a loopback or link-local address, which is not a valid webhook destination.", host)
		}
	}
	return u.String(), nil
}
