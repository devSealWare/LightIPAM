package agent

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/devSealWare/LightIPAM/internal/scanner"
)

// NameResolver is the minimal DNS surface the discoverer needs. It isolates the
// *net.Resolver dependency behind an interface so reverse/forward decoding and
// allowlist filtering stay unit-testable with a fake, never touching real DNS.
type NameResolver interface {
	// LookupAddr performs a reverse (PTR) lookup of an IP, returning its names.
	LookupAddr(ctx context.Context, addr string) ([]string, error)
	// LookupHost performs a forward lookup of a name, returning its addresses.
	LookupHost(ctx context.Context, host string) ([]string, error)
}

// DNSConfig configures the DNS enrichment backend. Server, when set, names an
// explicit resolver to query ("host" or "host:port", e.g. "192.168.1.1"); empty
// uses the agent's system resolver. Timeout bounds each individual lookup.
type DNSConfig struct {
	Server  string
	Timeout time.Duration
}

func (c DNSConfig) withDefaults() DNSConfig {
	if c.Timeout <= 0 {
		c.Timeout = 3 * time.Second
	}
	return c
}

// DNSDiscoverer resolves host names from the network's authoritative DNS without
// nmap or SNMP. Per target it does a reverse (PTR) lookup to learn the IP's name,
// then a forward (A) lookup to confirm that name maps back to the same IP. Where
// NameDiscoverer (NetBIOS/mDNS) recovers names for hosts with no DNS record, this
// reads the DNS the network already runs — the common case for managed hosts — and
// forward-confirms it. Both lookups are ordinary UDP/TCP/53 from a normal socket:
// no NET_RAW, no new privilege. It implements the Discoverer interface so the
// agent can route the dns_lookup scan type to it and the combined scan can fold it
// in.
type DNSDiscoverer struct {
	cfg     DNSConfig
	resolve NameResolver
}

// NewDNSDiscoverer returns a discoverer using the given settings (with sensible
// defaults filled in) and a *net.Resolver built from the config.
func NewDNSDiscoverer(cfg DNSConfig) *DNSDiscoverer {
	cfg = cfg.withDefaults()
	return &DNSDiscoverer{cfg: cfg, resolve: newResolver(cfg)}
}

// Discover resolves each target host over DNS and returns one observation per IP
// that has a PTR record. Targets must be single IPv4 hosts (a reverse lookup is
// per-address, so a CIDR is reported as skipped, not expanded); out-of-scope
// targets are dropped defensively. An address with no PTR record contributes a
// per-target ScanError rather than failing the whole job.
func (d *DNSDiscoverer) Discover(ctx context.Context, job scanner.ScanJob) ([]scanner.Observation, []scanner.ScanError, error) {
	if job.Mode == scanner.ModePassive {
		// Passive means "no packets on the wire"; a DNS query is active I/O.
		return []scanner.Observation{}, []scanner.ScanError{}, nil
	}
	if len(job.Targets) == 0 {
		return nil, nil, fmt.Errorf("DNS lookup has no target hosts")
	}

	scope, err := parseScopePrefixes(job.AllowedCIDRs)
	if err != nil {
		return nil, nil, fmt.Errorf("parse job allowlist: %w", err)
	}

	now := time.Now().UTC()
	observations := make([]scanner.Observation, 0, len(job.Targets))
	scanErrs := make([]scanner.ScanError, 0)

	for _, target := range job.Targets {
		select {
		case <-ctx.Done():
			return observations, scanErrs, ctx.Err()
		default:
		}

		addr, err := netip.ParseAddr(target)
		if err != nil || !addr.Is4() {
			// A CIDR (or anything not a single IPv4) cannot be reverse-resolved.
			scanErrs = append(scanErrs, scanner.ScanError{
				Code:    "dns_unresolved",
				Message: "DNS lookup needs single-host targets (cannot resolve a CIDR)",
				Target:  target,
			})
			continue
		}
		if !withinScope(addr, scope) {
			continue
		}

		obs, ok := d.lookup(ctx, target, now)
		if !ok {
			scanErrs = append(scanErrs, scanner.ScanError{
				Code:    "dns_unresolved",
				Message: "no PTR record for this address",
				Target:  target,
			})
			continue
		}
		observations = append(observations, obs)
	}

	return observations, scanErrs, nil
}

// lookup performs the reverse-then-forward DNS resolution for one IP. It returns
// ok=false when there is no usable PTR record. A forward lookup that maps the name
// back to the same IP is recorded as "forward-confirmed" evidence; a mismatch (or
// a forward lookup that fails) still keeps the name but is noted, so an operator
// can judge a stale or hijacked PTR.
func (d *DNSDiscoverer) lookup(ctx context.Context, ip string, now time.Time) (scanner.Observation, bool) {
	lookupCtx, cancel := context.WithTimeout(ctx, d.cfg.Timeout)
	defer cancel()

	names, err := d.resolve.LookupAddr(lookupCtx, ip)
	if err != nil {
		return scanner.Observation{}, false
	}
	name := ""
	for _, n := range names {
		if n = strings.TrimSuffix(strings.TrimSpace(n), "."); n != "" {
			name = n
			break
		}
	}
	if name == "" {
		return scanner.Observation{}, false
	}

	summary := "Reverse DNS (PTR): " + name
	if d.forwardConfirms(lookupCtx, name, ip) {
		summary += " (forward-confirmed)"
	} else {
		summary += " (forward lookup did not confirm)"
	}

	return scanner.Observation{
		IP:         ip,
		Hostname:   name,
		ObservedAt: now,
		Evidence:   []scanner.Evidence{{Source: "dns", Summary: summary}},
	}, true
}

// forwardConfirms reports whether a forward lookup of name yields ip, confirming
// the PTR record agrees with the A record. A lookup error or any non-matching
// answer is treated as unconfirmed (false) rather than fatal.
func (d *DNSDiscoverer) forwardConfirms(ctx context.Context, name, ip string) bool {
	addrs, err := d.resolve.LookupHost(ctx, name)
	if err != nil {
		return false
	}
	for _, a := range addrs {
		if a == ip {
			return true
		}
	}
	return false
}

// newResolver builds the *net.Resolver the discoverer uses. With no explicit
// server it returns the system resolver; with one set it returns a Go resolver
// that dials that server (defaulting to port 53), so an operator can point DNS
// enrichment at a specific internal resolver without changing the agent's host
// resolver configuration.
func newResolver(cfg DNSConfig) *net.Resolver {
	server := strings.TrimSpace(cfg.Server)
	if server == "" {
		return net.DefaultResolver
	}
	if _, _, err := net.SplitHostPort(server); err != nil {
		server = net.JoinHostPort(server, "53")
	}
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			dialer := net.Dialer{Timeout: cfg.Timeout}
			return dialer.DialContext(ctx, network, server)
		},
	}
}
