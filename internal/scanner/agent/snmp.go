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

// MIB-II OIDs read by an snmp_inventory scan. The system-group scalars (queried
// with a single Get, hence the trailing .0 instance) describe the device itself;
// the table column roots (walked) describe its interfaces and the IP addresses it
// owns. Joining ipAddrTable (IP→ifIndex) with ifTable (ifIndex→MAC/name) yields
// the IP↔MAC↔interface mapping for every address the device hosts.
const (
	oidSysDescr    = "1.3.6.1.2.1.1.1.0" // textual device description (vendor/model/OS)
	oidSysObjectID = "1.3.6.1.2.1.1.2.0" // vendor's authoritative device identification
	oidSysUpTime   = "1.3.6.1.2.1.1.3.0" // time since the management subsystem restarted
	oidSysContact  = "1.3.6.1.2.1.1.4.0" // administrative contact
	oidSysName     = "1.3.6.1.2.1.1.5.0" // administratively-assigned device name
	oidSysLocation = "1.3.6.1.2.1.1.6.0" // physical location

	oidIPAdEntIfIndex = "1.3.6.1.2.1.4.20.1.2" // ipAddrTable: row index is the IP, value is its ifIndex
	oidIfPhysAddress  = "1.3.6.1.2.1.2.2.1.6"  // ifTable: row index is the ifIndex, value is the MAC
	oidIfDescr        = "1.3.6.1.2.1.2.2.1.2"  // ifTable: row index is the ifIndex, value is the name
)

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
	Get(oids []string) (*gosnmp.SnmpPacket, error)
	BulkWalkAll(rootOID string) ([]gosnmp.SnmpPDU, error)
	Close() error
}

// snmpDialer opens (but does not connect) a session to one target device.
type snmpDialer func(target string, cfg SNMPConfig) (snmpSession, error)

// SNMPDiscoverer is the agent's SNMP discovery backend. Selected by scan type it
// performs two jobs over UDP/161: arp_table harvests IP↔MAC bindings from a
// gateway's ARP/neighbor cache, and snmp_inventory reads a device's own identity
// (system group) plus its interface/IP-address tables. Unlike nmap it sends no
// raw probes and needs no NET_RAW: an ordinary socket suffices. It implements the
// Discoverer interface so the agent can route both job types to it.
type SNMPDiscoverer struct {
	cfg  SNMPConfig
	dial snmpDialer
}

// NewSNMPDiscoverer returns a discoverer using the given SNMP settings (with
// sensible defaults filled in) and the real gosnmp dialer.
func NewSNMPDiscoverer(cfg SNMPConfig) *SNMPDiscoverer {
	return &SNMPDiscoverer{cfg: cfg.withDefaults(), dial: dialSNMP}
}

// Discover validates the common job preamble (passive short-circuit, version,
// targets, allowlist) and dispatches to the per-type harvester. Entries outside
// the job allowlist are always dropped so a scan never reports addresses it was
// not authorized to learn about, and a device that cannot be reached contributes
// a per-target ScanError but does not fail the whole job.
func (d *SNMPDiscoverer) Discover(ctx context.Context, job scanner.ScanJob) ([]scanner.Observation, []scanner.ScanError, error) {
	if job.Mode == scanner.ModePassive {
		// Passive means "no packets on the wire"; an SNMP query is active I/O.
		return []scanner.Observation{}, []scanner.ScanError{}, nil
	}
	if d.cfg.Version != SNMPv2c {
		return nil, nil, fmt.Errorf("SNMP version %q is not supported yet (only v2c)", d.cfg.Version)
	}
	if len(job.Targets) == 0 {
		return nil, nil, fmt.Errorf("SNMP scan has no target devices")
	}

	scope, err := parseScopePrefixes(job.AllowedCIDRs)
	if err != nil {
		return nil, nil, fmt.Errorf("parse job allowlist: %w", err)
	}

	now := time.Now().UTC()
	switch job.Type {
	case scanner.ScanSNMPInventory:
		return d.discoverInventory(ctx, job, scope, now)
	default:
		return d.discoverARP(ctx, job, scope, now)
	}
}

// discoverARP walks each target gateway's ARP/neighbor cache and returns one
// observation per cached neighbor whose IP falls within the allowlist, deduped
// across gateways (the first sighting wins).
func (d *SNMPDiscoverer) discoverARP(ctx context.Context, job scanner.ScanJob, scope []netip.Prefix, now time.Time) ([]scanner.Observation, []scanner.ScanError, error) {
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

// discoverInventory queries each target device's identity and interface/IP tables
// and returns one observation per in-scope IP it owns, enriched with the device's
// name, OS guess, and the owning interface's MAC. When a device answers but
// exposes no in-scope address, the target IP itself (if in scope) still records
// the device so the inventory is not lost. Observations are deduped by IP across
// targets.
func (d *SNMPDiscoverer) discoverInventory(ctx context.Context, job scanner.ScanJob, scope []netip.Prefix, now time.Time) ([]scanner.Observation, []scanner.ScanError, error) {
	observations := make([]scanner.Observation, 0)
	scanErrs := make([]scanner.ScanError, 0)
	index := make(map[string]int) // ip -> position in observations, for dedupe

	// add records an in-scope owned address (deduped by IP across targets). It
	// reports whether addr was in scope — independent of whether it was newly
	// appended — so the caller can tell a device that owns an in-scope address
	// (even one already seen on another target) from one that owns none.
	add := func(addr inventoryAddr, inv deviceInventory, target string) bool {
		ip, err := netip.ParseAddr(addr.ip)
		if err != nil || !ip.Is4() || !withinScope(ip, scope) {
			return false
		}
		if _, ok := index[addr.ip]; !ok {
			index[addr.ip] = len(observations)
			observations = append(observations, inv.observation(addr, now, target))
		}
		return true
	}

	for _, target := range job.Targets {
		select {
		case <-ctx.Done():
			return observations, scanErrs, ctx.Err()
		default:
		}

		inv, err := d.walkInventory(target)
		if err != nil {
			scanErrs = append(scanErrs, scanner.ScanError{
				Code:    "snmp_failed",
				Message: err.Error(),
				Target:  target,
			})
			continue
		}

		inScope := false
		for _, addr := range inv.addrs {
			if add(addr, inv, target) {
				inScope = true
			}
		}
		// Fallback: the device answered but owns no in-scope address. Record it
		// against the address we queried, when that is itself in scope.
		if !inScope {
			add(inventoryAddr{ip: target}, inv, target)
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

// ipFromARPOID extracts the IPv4 address from an ipNetToMediaTable row OID
// (…1.4.22.1.2.<ifIndex>.<a>.<b>.<c>.<d>). The address is the last four
// sub-identifiers, decoded by ipv4FromOIDSuffix.
func ipFromARPOID(oid string) (string, bool) {
	return ipv4FromOIDSuffix(oid)
}

// ipv4FromOIDSuffix extracts the IPv4 address encoded in the last four
// sub-identifiers of a table row OID. Both the ARP table
// (…22.1.2.<ifIndex>.<ip>) and the IP-address table (…4.20.1.2.<ip>) end their
// row index with the dotted-quad address.
func ipv4FromOIDSuffix(oid string) (string, bool) {
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

// ifIndexFromOIDSuffix extracts the interface index from the last sub-identifier
// of an ifTable row OID (…2.2.1.<col>.<ifIndex>).
func ifIndexFromOIDSuffix(oid string) (int, bool) {
	parts := strings.Split(strings.TrimPrefix(oid, "."), ".")
	if len(parts) == 0 {
		return 0, false
	}
	n, err := strconv.Atoi(parts[len(parts)-1])
	if err != nil || n < 0 {
		return 0, false
	}
	return n, true
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

// deviceInventory is the decoded SNMP view of one device: its system-group
// identity plus the per-interface MAC/name maps and the IP addresses it owns.
type deviceInventory struct {
	sysName     string
	sysDescr    string
	sysObjectID string
	sysContact  string
	sysLocation string
	sysUpTime   string         // human-readable, "" when unknown
	ifMAC       map[int]string // ifIndex -> MAC
	ifDescr     map[int]string // ifIndex -> interface name
	addrs       []inventoryAddr
}

// inventoryAddr is one IP the device owns and the interface it sits on. hasIf is
// false for the synthesized target-IP fallback, where the owning interface is
// unknown.
type inventoryAddr struct {
	ip      string
	ifIndex int
	hasIf   bool
}

// observation turns one owned address into an observation carrying the device's
// shared identity and the MAC of that address's interface (when known).
func (inv deviceInventory) observation(addr inventoryAddr, now time.Time, target string) scanner.Observation {
	obs := scanner.Observation{
		IP:         addr.ip,
		Hostname:   inv.sysName,
		OSDetail:   inv.sysDescr,
		OSFamily:   classifyOSFamily(inv.sysDescr),
		ObservedAt: now,
	}
	if addr.hasIf {
		obs.MAC = inv.ifMAC[addr.ifIndex]
	}
	obs.Evidence = inv.evidence(addr, target)
	return obs
}

// evidence renders the SNMP facts attached to an observation: always the source
// device, then the owning interface and any non-empty system-group detail.
func (inv deviceInventory) evidence(addr inventoryAddr, target string) []scanner.Evidence {
	ev := []scanner.Evidence{{Source: "snmp", Summary: "SNMP inventory from " + target, Raw: inv.sysDescr}}
	if addr.hasIf {
		if name := inv.ifDescr[addr.ifIndex]; name != "" {
			ev = append(ev, scanner.Evidence{Source: "snmp", Summary: fmt.Sprintf("Interface %s (ifIndex %d)", name, addr.ifIndex)})
		} else {
			ev = append(ev, scanner.Evidence{Source: "snmp", Summary: fmt.Sprintf("Interface ifIndex %d", addr.ifIndex)})
		}
	}
	if inv.sysLocation != "" {
		ev = append(ev, scanner.Evidence{Source: "snmp", Summary: "Location: " + inv.sysLocation})
	}
	if inv.sysContact != "" {
		ev = append(ev, scanner.Evidence{Source: "snmp", Summary: "Contact: " + inv.sysContact})
	}
	if inv.sysUpTime != "" {
		ev = append(ev, scanner.Evidence{Source: "snmp", Summary: "Uptime: " + inv.sysUpTime})
	}
	if inv.sysObjectID != "" {
		ev = append(ev, scanner.Evidence{Source: "snmp", Summary: "sysObjectID", Raw: inv.sysObjectID})
	}
	return ev
}

// walkInventory connects to one device and reads its system group plus its
// interface and IP-address tables. A failure to read the system group is fatal
// for the target (SNMP is not really answering); the table walks are best-effort
// enrichment, so a device that hides ifTable still yields its identity and any
// addresses it did expose.
func (d *SNMPDiscoverer) walkInventory(target string) (deviceInventory, error) {
	session, err := d.dial(target, d.cfg)
	if err != nil {
		return deviceInventory{}, fmt.Errorf("snmp dial %s: %w", target, err)
	}
	if err := session.Connect(); err != nil {
		return deviceInventory{}, fmt.Errorf("snmp connect %s: %w", target, err)
	}
	defer session.Close()

	inv := deviceInventory{ifMAC: map[int]string{}, ifDescr: map[int]string{}}

	pkt, err := session.Get([]string{oidSysDescr, oidSysObjectID, oidSysUpTime, oidSysContact, oidSysName, oidSysLocation})
	if err != nil {
		return deviceInventory{}, fmt.Errorf("snmp get system %s: %w", target, err)
	}
	if pkt != nil {
		for _, pdu := range pkt.Variables {
			switch normalizeOID(pdu.Name) {
			case oidSysDescr:
				inv.sysDescr = singleLine(octetString(pdu))
			case oidSysObjectID:
				inv.sysObjectID = oidValue(pdu)
			case oidSysUpTime:
				inv.sysUpTime = formatUptime(pdu)
			case oidSysContact:
				inv.sysContact = singleLine(octetString(pdu))
			case oidSysName:
				inv.sysName = singleLine(octetString(pdu))
			case oidSysLocation:
				inv.sysLocation = singleLine(octetString(pdu))
			}
		}
	}

	// ipAddrTable: IP -> ifIndex.
	if pdus, err := session.BulkWalkAll(oidIPAdEntIfIndex); err == nil {
		for _, pdu := range pdus {
			ip, ok := ipv4FromOIDSuffix(pdu.Name)
			if !ok {
				continue
			}
			ifIndex, ok := intFromPDU(pdu)
			if !ok {
				continue
			}
			inv.addrs = append(inv.addrs, inventoryAddr{ip: ip, ifIndex: ifIndex, hasIf: true})
		}
	}

	// ifTable: ifIndex -> MAC and ifIndex -> name (both best-effort).
	if pdus, err := session.BulkWalkAll(oidIfPhysAddress); err == nil {
		for _, pdu := range pdus {
			if ifIndex, ok := ifIndexFromOIDSuffix(pdu.Name); ok {
				if mac, ok := macFromPDU(pdu); ok {
					inv.ifMAC[ifIndex] = mac
				}
			}
		}
	}
	if pdus, err := session.BulkWalkAll(oidIfDescr); err == nil {
		for _, pdu := range pdus {
			if ifIndex, ok := ifIndexFromOIDSuffix(pdu.Name); ok {
				if name := singleLine(octetString(pdu)); name != "" {
					inv.ifDescr[ifIndex] = name
				}
			}
		}
	}

	return inv, nil
}

// normalizeOID strips a leading dot so OIDs compare regardless of whether the
// agent returns them in absolute (".1.3…") or relative ("1.3…") form.
func normalizeOID(oid string) string {
	return strings.TrimPrefix(oid, ".")
}

// octetString returns an SNMP OctetString PDU value as a string, tolerating the
// []byte and string representations and yielding "" for anything else (including
// NoSuchObject/NoSuchInstance, whose value is nil).
func octetString(pdu gosnmp.SnmpPDU) string {
	switch v := pdu.Value.(type) {
	case []byte:
		return string(v)
	case string:
		return v
	default:
		return ""
	}
}

// oidValue returns an ObjectIdentifier PDU value (e.g. sysObjectID) normalized
// without a leading dot.
func oidValue(pdu gosnmp.SnmpPDU) string {
	if s, ok := pdu.Value.(string); ok {
		return normalizeOID(s)
	}
	return ""
}

// intFromPDU returns an integer-valued PDU (e.g. ipAdEntIfIndex) as an int.
func intFromPDU(pdu gosnmp.SnmpPDU) (int, bool) {
	switch v := pdu.Value.(type) {
	case int:
		return v, true
	case int32:
		return int(v), true
	case int64:
		return int(v), true
	case uint:
		return int(v), true
	case uint32:
		return int(v), true
	case uint64:
		return int(v), true
	default:
		return 0, false
	}
}

// formatUptime renders a sysUpTime TimeTicks value (hundredths of a second) as a
// compact human-readable duration, or "" when it is missing or zero.
func formatUptime(pdu gosnmp.SnmpPDU) string {
	secs := gosnmp.ToBigInt(pdu.Value).Int64() / 100
	if secs <= 0 {
		return ""
	}
	days := secs / 86400
	hrs := (secs % 86400) / 3600
	mins := (secs % 3600) / 60
	switch {
	case days > 0:
		return fmt.Sprintf("%dd %dh %dm", days, hrs, mins)
	case hrs > 0:
		return fmt.Sprintf("%dh %dm", hrs, mins)
	default:
		return fmt.Sprintf("%dm", mins)
	}
}

// singleLine trims and collapses interior whitespace so a multi-line sysDescr
// renders as one tidy line.
func singleLine(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

// classifyOSFamily makes a best-effort OS-family guess from a device's sysDescr,
// returning "" when nothing recognizable matches. The full sysDescr is preserved
// separately as OSDetail, so this is only a coarse grouping hint.
func classifyOSFamily(sysDescr string) string {
	d := strings.ToLower(sysDescr)
	switch {
	case d == "":
		return ""
	case strings.Contains(d, "windows"):
		return "Windows"
	case strings.Contains(d, "cisco ios"), strings.Contains(d, "cisco nx-os"), strings.Contains(d, "cisco adaptive security"):
		return "Cisco IOS"
	case strings.Contains(d, "junos"), strings.Contains(d, "juniper"):
		return "JunOS"
	case strings.Contains(d, "routeros"), strings.Contains(d, "mikrotik"):
		return "RouterOS"
	case strings.Contains(d, "darwin"):
		return "macOS"
	case strings.Contains(d, "freebsd"), strings.Contains(d, "openbsd"), strings.Contains(d, "netbsd"):
		return "BSD"
	case strings.Contains(d, "linux"):
		return "Linux"
	default:
		return ""
	}
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

func (s *gosnmpSession) Get(oids []string) (*gosnmp.SnmpPacket, error) {
	return s.client.Get(oids)
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
