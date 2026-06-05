package agent

import (
	"context"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/devSealWare/LightIPAM/internal/scanner"
	"github.com/gosnmp/gosnmp"
)

// ipNetToMediaPhysAddress is the OID of the ARP/neighbor cache's physical-address
// column (RFC 1213 ipNetToMediaTable). Walking it yields one PDU per cache entry:
// the row index encodes the cached IPv4 address in the last four sub-identifiers,
// and the PDU value is the corresponding MAC. A single walk therefore recovers
// both halves of every IP↔MAC binding the device knows.
//
// The classic ipNetToMediaTable is IPv4-only but near-universally implemented;
// the newer ipNetToPhysicalTable (1.3.6.1.2.1.4.35) adds IPv6 and could layer in
// later. LightIPAM is IPv4-only today, matching the rest of the scanner.
const ipNetToMediaPhysAddress = "1.3.6.1.2.1.4.22.1.2"

// SNMPVersion selects the SNMP protocol version. Only v2c is wired today; the
// type and SNMPConfig leave room for v3 (user-based security) to drop in without
// reshaping the discoverer or its call sites.
type SNMPVersion string

const (
	SNMPv2c SNMPVersion = "2c"
	SNMPv3  SNMPVersion = "3" // reserved; not yet implemented
)

// SNMPConfig configures how the agent authenticates to and connects to SNMP
// devices. Community is the read credential for v2c. The v3 fields are reserved
// for a future SNMPv3 implementation and are ignored today; they exist so the
// agent's environment contract and this struct do not have to change later.
type SNMPConfig struct {
	Version   SNMPVersion
	Community string // v2c read community
	Port      uint16
	Timeout   time.Duration
	Retries   int

	// Reserved for SNMPv3 (user-based security model). Unused until v3 lands.
	SecurityName   string
	AuthProtocol   string
	AuthPassphrase string
	PrivProtocol   string
	PrivPassphrase string
}

func (c SNMPConfig) withDefaults() SNMPConfig {
	if c.Version == "" {
		c.Version = SNMPv2c
	}
	if strings.TrimSpace(c.Community) == "" {
		c.Community = "public"
	}
	if c.Port == 0 {
		c.Port = 161
	}
	if c.Timeout <= 0 {
		c.Timeout = 5 * time.Second
	}
	if c.Retries < 0 {
		c.Retries = 0
	}
	return c
}

// snmpSession is the minimal SNMP surface the discoverer needs. It isolates the
// gosnmp dependency behind an interface so OID/MAC parsing and allowlist
// filtering stay unit-testable with a fake, never touching a real device.
type snmpSession interface {
	Connect() error
	BulkWalkAll(rootOID string) ([]gosnmp.SnmpPDU, error)
	Close() error
}

// snmpDialer opens (but does not connect) a session to one target device.
type snmpDialer func(target string, cfg SNMPConfig) (snmpSession, error)

// SNMPDiscoverer harvests IP↔MAC bindings from the ARP/neighbor caches of one or
// more gateway/L3 devices over SNMP. Unlike nmap it sends no raw probes and needs
// no NET_RAW: it speaks UDP/161 from an ordinary socket. It implements the
// Discoverer interface so the agent can route ARP-table jobs to it by scan type.
type SNMPDiscoverer struct {
	cfg  SNMPConfig
	dial snmpDialer
}

// NewSNMPDiscoverer returns a discoverer using the given SNMP settings (with
// sensible defaults filled in) and the real gosnmp dialer.
func NewSNMPDiscoverer(cfg SNMPConfig) *SNMPDiscoverer {
	return &SNMPDiscoverer{cfg: cfg.withDefaults(), dial: dialSNMP}
}

// Discover queries every target device's ARP table and returns one observation
// per cached neighbor whose IP falls within the job allowlist. Entries outside
// the allowlist are dropped so a scan never reports addresses it was not
// authorized to learn about. A device that cannot be reached contributes a
// per-target ScanError but does not fail the whole job.
func (d *SNMPDiscoverer) Discover(ctx context.Context, job scanner.ScanJob) ([]scanner.Observation, []scanner.ScanError, error) {
	if job.Mode == scanner.ModePassive {
		// Passive means "no packets on the wire"; an SNMP query is active I/O.
		return []scanner.Observation{}, []scanner.ScanError{}, nil
	}
	if d.cfg.Version != SNMPv2c {
		return nil, nil, fmt.Errorf("SNMP version %q is not supported yet (only v2c)", d.cfg.Version)
	}
	if len(job.Targets) == 0 {
		return nil, nil, fmt.Errorf("ARP-table scan has no gateway targets")
	}

	scope, err := parseScopePrefixes(job.AllowedCIDRs)
	if err != nil {
		return nil, nil, fmt.Errorf("parse job allowlist: %w", err)
	}

	now := time.Now().UTC()
	observations := make([]scanner.Observation, 0)
	scanErrs := make([]scanner.ScanError, 0)
	index := make(map[string]int) // ip -> position in observations, for dedupe

	for _, target := range job.Targets {
		select {
		case <-ctx.Done():
			return observations, scanErrs, ctx.Err()
		default:
		}

		entries, err := d.walkARP(target)
		if err != nil {
			scanErrs = append(scanErrs, scanner.ScanError{
				Code:    "snmp_failed",
				Message: err.Error(),
				Target:  target,
			})
			continue
		}

		for _, e := range entries {
			addr, err := netip.ParseAddr(e.ip)
			if err != nil || !addr.Is4() || !withinScope(addr, scope) {
				continue
			}
			if _, ok := index[e.ip]; ok {
				// Same neighbor cached on more than one gateway: keep the first.
				continue
			}
			index[e.ip] = len(observations)
			observations = append(observations, scanner.Observation{
				IP:         e.ip,
				MAC:        e.mac,
				ObservedAt: now,
				Evidence: []scanner.Evidence{{
					Source:  "snmp",
					Summary: fmt.Sprintf("ARP/neighbor entry from gateway %s", target),
				}},
			})
		}
	}

	return observations, scanErrs, nil
}

// arpEntry is one decoded ipNetToMediaTable row.
type arpEntry struct {
	ip  string
	mac string
}

// walkARP connects to one device and walks its ARP table into decoded entries.
func (d *SNMPDiscoverer) walkARP(target string) ([]arpEntry, error) {
	session, err := d.dial(target, d.cfg)
	if err != nil {
		return nil, fmt.Errorf("snmp dial %s: %w", target, err)
	}
	if err := session.Connect(); err != nil {
		return nil, fmt.Errorf("snmp connect %s: %w", target, err)
	}
	defer session.Close()

	pdus, err := session.BulkWalkAll(ipNetToMediaPhysAddress)
	if err != nil {
		return nil, fmt.Errorf("snmp walk %s: %w", target, err)
	}
	return parseARPPDUs(pdus), nil
}

// parseARPPDUs decodes ipNetToMediaPhysAddress PDUs into IP↔MAC entries, skipping
// rows whose index is not a valid IPv4 address or whose value is not a usable MAC.
func parseARPPDUs(pdus []gosnmp.SnmpPDU) []arpEntry {
	entries := make([]arpEntry, 0, len(pdus))
	for _, pdu := range pdus {
		ip, ok := ipFromARPOID(pdu.Name)
		if !ok {
			continue
		}
		mac, ok := macFromPDU(pdu)
		if !ok {
			continue
		}
		entries = append(entries, arpEntry{ip: ip, mac: mac})
	}
	return entries
}

// ipFromARPOID extracts the IPv4 address encoded in the last four sub-identifiers
// of an ipNetToMediaTable row OID (…1.4.22.1.2.<ifIndex>.<a>.<b>.<c>.<d>).
func ipFromARPOID(oid string) (string, bool) {
	parts := strings.Split(strings.TrimPrefix(oid, "."), ".")
	if len(parts) < 4 {
		return "", false
	}
	var octets [4]byte
	for i, p := range parts[len(parts)-4:] {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 || n > 255 {
			return "", false
		}
		octets[i] = byte(n)
	}
	return netip.AddrFrom4(octets).String(), true
}

// macFromPDU formats an OctetString PDU value as a colon-separated MAC, rejecting
// non-octet-string values, wrong lengths, and the all-zero (incomplete) address.
func macFromPDU(pdu gosnmp.SnmpPDU) (string, bool) {
	raw, ok := pdu.Value.([]byte)
	if !ok || len(raw) != 6 {
		return "", false
	}
	allZero := true
	for _, b := range raw {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return "", false
	}
	hex := make([]string, len(raw))
	for i, b := range raw {
		hex[i] = fmt.Sprintf("%02x", b)
	}
	return strings.Join(hex, ":"), true
}

// dialSNMP is the production snmpDialer: it builds a gosnmp client for the target
// from the config. Connect() is called later by walkARP.
func dialSNMP(target string, cfg SNMPConfig) (snmpSession, error) {
	client := &gosnmp.GoSNMP{
		Target:    target,
		Port:      cfg.Port,
		Transport: "udp",
		Community: cfg.Community,
		Version:   gosnmp.Version2c,
		Timeout:   cfg.Timeout,
		Retries:   cfg.Retries,
		MaxOids:   gosnmp.MaxOids,
	}
	return &gosnmpSession{client: client}, nil
}

// gosnmpSession adapts *gosnmp.GoSNMP to the snmpSession interface.
type gosnmpSession struct {
	client *gosnmp.GoSNMP
}

func (s *gosnmpSession) Connect() error {
	return s.client.Connect()
}

func (s *gosnmpSession) BulkWalkAll(rootOID string) ([]gosnmp.SnmpPDU, error) {
	return s.client.BulkWalkAll(rootOID)
}

func (s *gosnmpSession) Close() error {
	if s.client.Conn != nil {
		return s.client.Conn.Close()
	}
	return nil
}

// parseScopePrefixes parses the job allowlist into masked IPv4 prefixes used to
// filter which cached neighbors a scan is allowed to report.
func parseScopePrefixes(cidrs []string) ([]netip.Prefix, error) {
	prefixes := make([]netip.Prefix, 0, len(cidrs))
	for _, c := range cidrs {
		p, err := netip.ParsePrefix(c)
		if err != nil {
			return nil, fmt.Errorf("parse allowed CIDR %q: %w", c, err)
		}
		prefixes = append(prefixes, p.Masked())
	}
	return prefixes, nil
}

func withinScope(addr netip.Addr, prefixes []netip.Prefix) bool {
	for _, p := range prefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}
