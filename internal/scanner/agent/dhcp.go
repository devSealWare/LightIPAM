package agent

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/devSealWare/LightIPAM/internal/scanner"
)

// errNoLeaseFile is the sentinel returned by the lease reader when no lease-file
// path is configured, so Discover can report a clear "not configured" notice
// rather than a generic read error.
var errNoLeaseFile = errors.New("no DHCP lease file configured")

// DHCPConfig configures the DHCP lease-ingestion backend. LeaseFile is the path to
// the DHCP server's lease file the agent can read (mounted into the agent
// read-only); Format selects the parser ("isc", "dnsmasq", or "" / "auto" to sniff
// the file).
type DHCPConfig struct {
	LeaseFile string
	Format    string
}

// leaseReader returns the raw bytes of the configured lease file. It is a function
// value so the parsers are unit-tested against fixture bytes with no filesystem.
type leaseReader func() ([]byte, error)

// dhcpLease is one decoded, active DHCP lease.
type dhcpLease struct {
	ip       string
	mac      string
	hostname string
	expires  time.Time // zero when unknown/infinite
}

// DHCPDiscoverer ingests active leases from a DHCP server's lease file, recovering
// the authoritative IP↔MAC binding and the client-supplied hostname for each lease.
// On a small LAN the DHCP server (often the router) is the most reliable source of
// both the MAC and a host's real name. Reading a file needs no extra privilege; the
// lease file path lives on the agent. It implements the Discoverer interface so the
// agent can route the dhcp_leases scan type to it and the combined scan can fold it
// in.
type DHCPDiscoverer struct {
	cfg  DHCPConfig
	read leaseReader
}

// NewDHCPDiscoverer returns a discoverer that reads the configured lease file. When
// no file is configured the reader yields errNoLeaseFile, which Discover turns into
// a clear notice instead of failing.
func NewDHCPDiscoverer(cfg DHCPConfig) *DHCPDiscoverer {
	d := &DHCPDiscoverer{cfg: cfg}
	d.read = func() ([]byte, error) {
		path := strings.TrimSpace(cfg.LeaseFile)
		if path == "" {
			return nil, errNoLeaseFile
		}
		return os.ReadFile(path)
	}
	return d
}

// Discover reads the lease file, parses it, and returns one observation per active
// lease whose IP falls within a target range. A missing or unconfigured lease file
// is a per-job notice (so a combined scan ignores it), not a hard error.
func (d *DHCPDiscoverer) Discover(ctx context.Context, job scanner.ScanJob) ([]scanner.Observation, []scanner.ScanError, error) {
	if job.Mode == scanner.ModePassive {
		return []scanner.Observation{}, []scanner.ScanError{}, nil
	}

	scope, err := scopeFromTargets(job.Targets)
	if err != nil {
		return nil, nil, fmt.Errorf("parse dhcp targets: %w", err)
	}

	data, err := d.read()
	if err != nil {
		if errors.Is(err, errNoLeaseFile) {
			return nil, []scanner.ScanError{{
				Code:    "dhcp_unconfigured",
				Message: "no DHCP lease file configured (set AGENT_DHCP_LEASE_FILE on the agent)",
			}}, nil
		}
		return nil, []scanner.ScanError{{
			Code:    "dhcp_failed",
			Message: "read lease file: " + err.Error(),
		}}, nil
	}

	leases, err := parseLeases(data, d.cfg.Format)
	if err != nil {
		return nil, []scanner.ScanError{{Code: "dhcp_failed", Message: err.Error()}}, nil
	}

	now := time.Now().UTC()
	observations := make([]scanner.Observation, 0, len(leases))
	for _, lease := range leases {
		addr, err := netip.ParseAddr(lease.ip)
		if err != nil || !addr.Is4() || !withinScope(addr, scope) {
			continue
		}
		summary := "DHCP lease (active)"
		if !lease.expires.IsZero() {
			summary = "DHCP lease (active), expires " + lease.expires.Format("2006-01-02 15:04 MST")
		}
		observations = append(observations, scanner.Observation{
			IP:         lease.ip,
			MAC:        lease.mac,
			Hostname:   lease.hostname,
			ObservedAt: now,
			Evidence:   []scanner.Evidence{{Source: "dhcp", Summary: summary}},
		})
	}
	return observations, []scanner.ScanError{}, nil
}

// scopeFromTargets turns each job target — a bare IPv4 host or a CIDR — into a
// prefix, so a lease's IP can be tested for containment. A host becomes a /32.
func scopeFromTargets(targets []string) ([]netip.Prefix, error) {
	prefixes := make([]netip.Prefix, 0, len(targets))
	for _, t := range targets {
		if p, err := netip.ParsePrefix(t); err == nil {
			prefixes = append(prefixes, p.Masked())
			continue
		}
		if a, err := netip.ParseAddr(t); err == nil {
			prefixes = append(prefixes, netip.PrefixFrom(a, a.BitLen()))
			continue
		}
		return nil, fmt.Errorf("target %q is not an IPv4 address or CIDR", t)
	}
	return prefixes, nil
}

// parseLeases decodes a lease file in the given format, deduping by IP (the last
// lease for an IP wins, since servers append newer leases). An empty/"auto" format
// sniffs the content.
func parseLeases(data []byte, format string) ([]dhcpLease, error) {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "isc":
		return parseISCLeases(data), nil
	case "dnsmasq":
		return parseDnsmasqLeases(data), nil
	case "", "auto":
		if looksLikeISC(data) {
			return parseISCLeases(data), nil
		}
		return parseDnsmasqLeases(data), nil
	default:
		return nil, fmt.Errorf("unknown DHCP lease format %q (use isc, dnsmasq, or auto)", format)
	}
}

// looksLikeISC reports whether the content looks like an ISC dhcpd.leases file: a
// line beginning with "lease " (the dnsmasq format has no such keyword).
func looksLikeISC(data []byte) bool {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "lease ") && strings.HasSuffix(line, "{") {
			return true
		}
	}
	return false
}

// parseDnsmasqLeases decodes the dnsmasq leases format: one lease per line as
// "<expiry-epoch> <mac> <ip> <hostname> <client-id>". A hostname of "*" means
// unknown. Expiry 0 means the lease never expires.
func parseDnsmasqLeases(data []byte) []dhcpLease {
	byIP := map[string]dhcpLease{}
	order := []string{}
	scan := bufio.NewScanner(bytes.NewReader(data))
	for scan.Scan() {
		fields := strings.Fields(scan.Text())
		if len(fields) < 4 {
			continue
		}
		lease := dhcpLease{mac: normalizeMAC(fields[1]), ip: fields[2]}
		if h := fields[3]; h != "" && h != "*" {
			lease.hostname = h
		}
		if epoch, err := strconv.ParseInt(fields[0], 10, 64); err == nil && epoch > 0 {
			lease.expires = time.Unix(epoch, 0).UTC()
		}
		if lease.ip == "" {
			continue
		}
		if _, seen := byIP[lease.ip]; !seen {
			order = append(order, lease.ip)
		}
		byIP[lease.ip] = lease
	}
	return collectLeases(byIP, order)
}

// parseISCLeases decodes the ISC dhcpd.leases format: "lease <ip> { ... }" blocks.
// Only leases with "binding state active" are returned; a server appends newer
// blocks for the same IP, so the last active block wins.
func parseISCLeases(data []byte) []dhcpLease {
	byIP := map[string]dhcpLease{}
	order := []string{}
	scan := bufio.NewScanner(bytes.NewReader(data))

	var cur dhcpLease
	var active, inBlock bool
	for scan.Scan() {
		line := strings.TrimSpace(scan.Text())
		switch {
		case strings.HasPrefix(line, "lease ") && strings.HasSuffix(line, "{"):
			cur = dhcpLease{ip: strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(line, "lease "), "{"))}
			active, inBlock = false, true
		case line == "}" && inBlock:
			if active && cur.ip != "" {
				if _, seen := byIP[cur.ip]; !seen {
					order = append(order, cur.ip)
				}
				byIP[cur.ip] = cur
			}
			inBlock = false
		case inBlock:
			parseISCLeaseLine(line, &cur, &active)
		}
	}
	return collectLeases(byIP, order)
}

// parseISCLeaseLine folds one statement inside an ISC lease block into cur.
func parseISCLeaseLine(line string, cur *dhcpLease, active *bool) {
	stmt := strings.TrimSuffix(line, ";")
	switch {
	case stmt == "binding state active":
		*active = true
	case strings.HasPrefix(stmt, "hardware ethernet "):
		cur.mac = normalizeMAC(strings.TrimPrefix(stmt, "hardware ethernet "))
	case strings.HasPrefix(stmt, "client-hostname "):
		cur.hostname = strings.Trim(strings.TrimPrefix(stmt, "client-hostname "), `"`)
	case strings.HasPrefix(stmt, "ends "):
		// "ends <weekday> YYYY/MM/DD HH:MM:SS" (UTC); "ends never" has no time.
		if t, ok := parseISCTime(stmt); ok {
			cur.expires = t
		}
	}
}

// parseISCTime parses an ISC "ends" statement's timestamp ("ends 4 2023/11/16
// 12:00:00"). It returns ok=false for "ends never" or an unparseable value.
func parseISCTime(stmt string) (time.Time, bool) {
	fields := strings.Fields(stmt) // ["ends", "<weekday>", "<date>", "<time>"]
	if len(fields) < 4 {
		return time.Time{}, false
	}
	t, err := time.Parse("2006/01/02 15:04:05", fields[2]+" "+fields[3])
	if err != nil {
		return time.Time{}, false
	}
	return t.UTC(), true
}

// collectLeases returns the deduped leases in first-seen order.
func collectLeases(byIP map[string]dhcpLease, order []string) []dhcpLease {
	out := make([]dhcpLease, 0, len(order))
	for _, ip := range order {
		out = append(out, byIP[ip])
	}
	return out
}

// normalizeMAC lowercases a MAC and drops a trailing "*"/empty marker; the
// import-time OUI lookup canonicalizes the rest.
func normalizeMAC(mac string) string {
	mac = strings.TrimSpace(strings.ToLower(mac))
	if mac == "*" {
		return ""
	}
	return mac
}
