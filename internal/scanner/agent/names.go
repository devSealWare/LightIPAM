package agent

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/devSealWare/LightIPAM/internal/scanner"
)

// Default ports for the two name protocols. NetBIOS name service (NBNS) listens
// on UDP/137; multicast DNS (mDNS) on UDP/5353. Both are queried with ordinary
// unicast UDP — no raw sockets, no NET_RAW.
const (
	defaultNetBIOSPort uint16 = 137
	defaultMDNSPort    uint16 = 5353
)

// NameConfig configures the name-resolution backend. Timeout bounds each
// individual UDP probe (a host that does not run the service simply never
// answers, so the probe relies on this short timeout to give up).
type NameConfig struct {
	NetBIOSPort uint16
	MDNSPort    uint16
	Timeout     time.Duration
}

func (c NameConfig) withDefaults() NameConfig {
	if c.NetBIOSPort == 0 {
		c.NetBIOSPort = defaultNetBIOSPort
	}
	if c.MDNSPort == 0 {
		c.MDNSPort = defaultMDNSPort
	}
	if c.Timeout <= 0 {
		c.Timeout = 2 * time.Second
	}
	return c
}

// udpExchanger sends one UDP datagram to addr and returns the first response
// datagram. It isolates the socket I/O behind a function value so the NetBIOS and
// mDNS packet encoders and parsers stay unit-testable with a fake, never touching
// the network.
type udpExchanger func(ctx context.Context, addr string, payload []byte, timeout time.Duration) ([]byte, error)

// NameDiscoverer resolves human-readable host names without nmap or SNMP, over
// two unprivileged UDP protocols: a NetBIOS node-status query (UDP/137) returns a
// Windows/Samba host's machine name and workgroup, and a unicast mDNS reverse
// query (UDP/5353) returns an Apple/Linux/IoT host's ".local" name. It recovers
// names for hosts that have no DNS PTR record — common on small-business LANs —
// and, for NetBIOS, works across subnets (the query is unicast, unlike
// multicast-only mDNS). It implements the Discoverer interface so the agent can
// route the name_lookup scan type to it and the combined scan can fold it in.
type NameDiscoverer struct {
	cfg      NameConfig
	exchange udpExchanger
}

// NewNameDiscoverer returns a discoverer using the given settings (with sensible
// defaults filled in) and the real UDP exchanger.
func NewNameDiscoverer(cfg NameConfig) *NameDiscoverer {
	return &NameDiscoverer{cfg: cfg.withDefaults(), exchange: udpExchange}
}

// Discover queries each target host over NetBIOS and mDNS and returns one
// observation per host whose name it learns. Targets must be single IPv4 hosts
// (a name probe is a unicast query to one device, so a CIDR is reported as
// skipped, not expanded); out-of-scope targets are dropped defensively. A host
// that answers neither protocol contributes a per-target ScanError rather than
// failing the whole job — most hosts simply do not run these services.
func (d *NameDiscoverer) Discover(ctx context.Context, job scanner.ScanJob) ([]scanner.Observation, []scanner.ScanError, error) {
	if job.Mode == scanner.ModePassive {
		// Passive means "no packets on the wire"; a name query is active I/O.
		return []scanner.Observation{}, []scanner.ScanError{}, nil
	}
	if len(job.Targets) == 0 {
		return nil, nil, fmt.Errorf("name lookup has no target hosts")
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
			// A CIDR (or anything not a single IPv4) cannot be unicast-probed.
			scanErrs = append(scanErrs, scanner.ScanError{
				Code:    "name_unresolved",
				Message: "name lookup needs single-host targets (cannot probe a CIDR)",
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
				Code:    "name_unresolved",
				Message: "no NetBIOS or mDNS name (host may not run those services)",
				Target:  target,
			})
			continue
		}
		observations = append(observations, obs)
	}

	return observations, scanErrs, nil
}

// lookup queries one host over NetBIOS (UDP/137) and mDNS (UDP/5353) and folds
// whatever names it learns into a single observation. It returns ok=false when
// neither protocol answered with a usable name. Both probes are attempted even if
// the first succeeds, so a host that answers both (rare) records both as evidence.
func (d *NameDiscoverer) lookup(ctx context.Context, ip string, now time.Time) (scanner.Observation, bool) {
	obs := scanner.Observation{IP: ip, ObservedAt: now}
	found := false

	if name, group, err := d.queryNetBIOS(ctx, ip); err == nil && name != "" {
		obs.Hostname = name
		found = true
		summary := "NetBIOS name: " + name
		if group != "" {
			summary += " (workgroup " + group + ")"
		}
		obs.Evidence = append(obs.Evidence, scanner.Evidence{Source: "netbios", Summary: summary})
	}

	if name, err := d.queryMDNS(ctx, ip); err == nil && name != "" {
		// NetBIOS (and, in a combined scan, nmap's PTR) lead; mDNS fills the
		// hostname only when nothing else named the host, but always rides as
		// evidence so the ".local" name is recorded.
		if obs.Hostname == "" {
			obs.Hostname = strings.TrimSuffix(name, ".local")
		}
		found = true
		obs.Evidence = append(obs.Evidence, scanner.Evidence{Source: "mdns", Summary: "mDNS name: " + name})
	}

	return obs, found
}

// queryNetBIOS sends a NetBIOS node-status request to the host and decodes its
// machine name and workgroup from the reply.
func (d *NameDiscoverer) queryNetBIOS(ctx context.Context, ip string) (name, group string, err error) {
	addr := net.JoinHostPort(ip, strconv.Itoa(int(d.cfg.NetBIOSPort)))
	resp, err := d.exchange(ctx, addr, nbstatRequest(), d.cfg.Timeout)
	if err != nil {
		return "", "", err
	}
	return parseNBStatResponse(resp)
}

// queryMDNS sends a unicast mDNS reverse-lookup query to the host and decodes the
// ".local" name from the first PTR answer.
func (d *NameDiscoverer) queryMDNS(ctx context.Context, ip string) (string, error) {
	query, err := mdnsReverseRequest(ip)
	if err != nil {
		return "", err
	}
	addr := net.JoinHostPort(ip, strconv.Itoa(int(d.cfg.MDNSPort)))
	resp, err := d.exchange(ctx, addr, query, d.cfg.Timeout)
	if err != nil {
		return "", err
	}
	return parseMDNSPTRResponse(resp)
}

// udpExchange is the production udpExchanger: it dials a connected UDP socket to
// addr, writes payload, and reads the first response datagram. A connected socket
// only receives datagrams from the dialed peer, so a stray response from another
// host is ignored. The deadline is the sooner of the per-probe timeout and any
// deadline already on ctx.
func udpExchange(ctx context.Context, addr string, payload []byte, timeout time.Duration) ([]byte, error) {
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "udp", addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	deadline := time.Now().Add(timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = conn.SetDeadline(deadline)

	if _, err := conn.Write(payload); err != nil {
		return nil, err
	}
	// NBSTAT and mDNS responses fit comfortably in a single datagram.
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

// --- NetBIOS node status (NBSTAT) ---

// nbstatRequest builds a NetBIOS node-status request for the wildcard name "*",
// which asks a host to enumerate the NetBIOS names it has registered. The packet
// is the classic NBNS format: a 12-byte header followed by one question carrying
// the first-level-encoded name, QTYPE NBSTAT (0x21) and QCLASS IN (0x01).
func nbstatRequest() []byte {
	buf := make([]byte, 0, 50)
	// Header: arbitrary transaction id (echoed back), flags 0 (standard query),
	// QDCOUNT 1, and zero answer/authority/additional counts.
	buf = append(buf,
		0x4c, 0x49, // transaction id
		0x00, 0x00, // flags
		0x00, 0x01, // QDCOUNT = 1
		0x00, 0x00, // ANCOUNT
		0x00, 0x00, // NSCOUNT
		0x00, 0x00, // ARCOUNT
	)
	encoded := encodeNetBIOSName("*")
	buf = append(buf, byte(len(encoded))) // label length, always 0x20 (32)
	buf = append(buf, encoded...)
	buf = append(buf, 0x00)       // root label terminator
	buf = append(buf, 0x00, 0x21) // QTYPE = NBSTAT
	buf = append(buf, 0x00, 0x01) // QCLASS = IN
	return buf
}

// encodeNetBIOSName applies NetBIOS first-level (half-ASCII) encoding: the 16-byte
// NetBIOS name — the given name space-padded to 15 bytes plus a trailing suffix
// byte (0 here) — is expanded so each byte becomes two letters, the high and low
// nibble each added to 'A'. The wildcard "*" is special-cased to '*' followed by
// 15 NUL bytes, which is what a node-status query uses.
func encodeNetBIOSName(name string) []byte {
	var raw [16]byte
	if name == "*" {
		raw[0] = '*'
		// The remaining bytes stay zero.
	} else {
		for i := 0; i < 15; i++ {
			if i < len(name) {
				raw[i] = name[i]
			} else {
				raw[i] = ' '
			}
		}
	}
	out := make([]byte, 0, 32)
	for _, b := range raw {
		out = append(out, 'A'+(b>>4), 'A'+(b&0x0f))
	}
	return out
}

// parseNBStatResponse decodes a NetBIOS node-status response into the host's
// machine name and workgroup. The layout is a 12-byte header, the echoed RR name,
// the RR fixed fields, then the node-status payload: a one-byte name count
// followed by that many 18-byte entries (15-byte space-padded name, 1-byte
// suffix, 2-byte flags). The unique name with suffix 0x00 is the machine
// (Workstation Service) name; the group name with suffix 0x00 is the workgroup.
func parseNBStatResponse(resp []byte) (name, group string, err error) {
	const headerLen = 12
	if len(resp) < headerLen+1 {
		return "", "", fmt.Errorf("netbios response too short")
	}

	// Skip the header and the echoed RR name (length-prefixed labels ending in a
	// zero byte).
	pos, err := skipName(resp, headerLen)
	if err != nil {
		return "", "", err
	}
	// RR fixed fields: TYPE(2) CLASS(2) TTL(4) RDLENGTH(2) = 10 bytes, then the
	// one-byte name count.
	pos += 10
	if pos >= len(resp) {
		return "", "", fmt.Errorf("netbios response truncated before name count")
	}
	count := int(resp[pos])
	pos++

	for i := 0; i < count; i++ {
		if pos+18 > len(resp) {
			break
		}
		entry := resp[pos : pos+18]
		pos += 18

		rawName := strings.TrimRight(string(entry[:15]), " \x00")
		suffix := entry[15]
		flags := binary.BigEndian.Uint16(entry[16:18])
		isGroup := flags&0x8000 != 0

		// Only the suffix-0x00 names identify the host: unique = machine name,
		// group = workgroup/domain. Other suffixes name services (file server,
		// messenger, ...) we do not surface.
		if suffix != 0x00 || rawName == "" {
			continue
		}
		if isGroup {
			if group == "" {
				group = rawName
			}
		} else if name == "" {
			name = rawName
		}
	}

	if name == "" && group == "" {
		return "", "", fmt.Errorf("no NetBIOS names in response")
	}
	return name, group, nil
}

// --- mDNS reverse lookup ---

// mdnsReverseRequest builds a unicast mDNS reverse-lookup query for ip: a PTR
// question for the host's <reversed-octets>.in-addr.arpa name, with the QU
// (unicast-response) bit set in QCLASS so a responder replies directly to us
// instead of multicasting. A responder (Bonjour/avahi) answers with its own
// ".local" host name.
func mdnsReverseRequest(ip string) ([]byte, error) {
	addr, err := netip.ParseAddr(ip)
	if err != nil || !addr.Is4() {
		return nil, fmt.Errorf("mdns reverse query needs an IPv4 address, got %q", ip)
	}
	o := addr.As4()
	qname := fmt.Sprintf("%d.%d.%d.%d.in-addr.arpa", o[3], o[2], o[1], o[0])

	buf := make([]byte, 0, 64)
	buf = append(buf,
		0x00, 0x00, // id (0 for mDNS)
		0x00, 0x00, // flags: standard query
		0x00, 0x01, // QDCOUNT = 1
		0x00, 0x00, // ANCOUNT
		0x00, 0x00, // NSCOUNT
		0x00, 0x00, // ARCOUNT
	)
	buf = appendDNSName(buf, qname)
	buf = append(buf, 0x00, 0x0c) // QTYPE = PTR
	buf = append(buf, 0x80, 0x01) // QCLASS = IN with the QU (unicast-response) bit
	return buf, nil
}

// appendDNSName encodes a dotted DNS name as length-prefixed labels terminated by
// a zero byte.
func appendDNSName(buf []byte, name string) []byte {
	for _, label := range strings.Split(name, ".") {
		if label == "" {
			continue
		}
		buf = append(buf, byte(len(label)))
		buf = append(buf, label...)
	}
	return append(buf, 0x00)
}

// parseMDNSPTRResponse decodes an mDNS response and returns the target name from
// its first PTR answer record (the host's ".local" name). It skips the question
// section to reach the answers, then walks them for a PTR whose RDATA decodes —
// following DNS compression — to a domain name.
func parseMDNSPTRResponse(resp []byte) (string, error) {
	const headerLen = 12
	if len(resp) < headerLen {
		return "", fmt.Errorf("mdns response too short")
	}
	qd := int(binary.BigEndian.Uint16(resp[4:6]))
	an := int(binary.BigEndian.Uint16(resp[6:8]))
	if an == 0 {
		return "", fmt.Errorf("mdns response has no answers")
	}

	pos := headerLen
	// Skip the question section: each question is a name then QTYPE(2)+QCLASS(2).
	for i := 0; i < qd; i++ {
		var err error
		pos, err = skipName(resp, pos)
		if err != nil {
			return "", err
		}
		pos += 4
		if pos > len(resp) {
			return "", fmt.Errorf("mdns question truncated")
		}
	}

	for i := 0; i < an; i++ {
		// Answer: NAME, TYPE(2), CLASS(2), TTL(4), RDLENGTH(2), RDATA.
		var err error
		pos, err = skipName(resp, pos)
		if err != nil {
			return "", err
		}
		if pos+10 > len(resp) {
			return "", fmt.Errorf("mdns answer truncated")
		}
		rrType := binary.BigEndian.Uint16(resp[pos : pos+2])
		rdlen := int(binary.BigEndian.Uint16(resp[pos+8 : pos+10]))
		rdataStart := pos + 10
		if rdataStart+rdlen > len(resp) {
			return "", fmt.Errorf("mdns rdata truncated")
		}
		if rrType == 0x000c { // PTR
			ptrName, _, err := readDNSName(resp, rdataStart)
			if err != nil {
				return "", err
			}
			if ptrName = strings.TrimSuffix(ptrName, "."); ptrName != "" {
				return ptrName, nil
			}
		}
		pos = rdataStart + rdlen
	}
	return "", fmt.Errorf("mdns response has no PTR answer")
}

// --- DNS/NetBIOS name helpers ---

// skipName advances past a sequence of length-prefixed labels terminated by a
// zero-length label, returning the offset just after the terminator (or just
// after a compression pointer, which ends a name in two bytes). It does not
// resolve pointers; use readDNSName to decode a name's contents.
func skipName(buf []byte, pos int) (int, error) {
	for {
		if pos >= len(buf) {
			return 0, fmt.Errorf("name runs past end of packet")
		}
		n := int(buf[pos])
		if n == 0 {
			return pos + 1, nil
		}
		if n&0xc0 == 0xc0 {
			// Compression pointer: two bytes total, and it terminates the name.
			if pos+1 >= len(buf) {
				return 0, fmt.Errorf("compression pointer truncated")
			}
			return pos + 2, nil
		}
		pos += 1 + n
	}
}

// readDNSName decodes a DNS name starting at pos, following compression pointers,
// and returns the dotted name plus the offset of the byte just after the name in
// the record (after the terminating zero or the first pointer). A hop limit
// guards against pointer loops in a malformed packet.
func readDNSName(buf []byte, pos int) (string, int, error) {
	var labels []string
	next := -1
	hops := 0
	for {
		if pos >= len(buf) {
			return "", 0, fmt.Errorf("dns name runs past end of packet")
		}
		n := int(buf[pos])
		switch {
		case n == 0:
			pos++
			if next == -1 {
				next = pos
			}
			return strings.Join(labels, "."), next, nil
		case n&0xc0 == 0xc0:
			if pos+1 >= len(buf) {
				return "", 0, fmt.Errorf("dns compression pointer truncated")
			}
			ptr := int(binary.BigEndian.Uint16(buf[pos:pos+2]) & 0x3fff)
			if next == -1 {
				next = pos + 2
			}
			hops++
			if hops > 16 {
				return "", 0, fmt.Errorf("dns name compression loop")
			}
			pos = ptr
		default:
			start := pos + 1
			end := start + n
			if end > len(buf) {
				return "", 0, fmt.Errorf("dns label runs past end of packet")
			}
			labels = append(labels, string(buf[start:end]))
			pos = end
		}
	}
}
