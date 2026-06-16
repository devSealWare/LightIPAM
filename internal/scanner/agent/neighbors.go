package agent

import (
	"context"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/devSealWare/LightIPAM/internal/scanner"
)

// CISCO-CDP-MIB cdpCacheTable columns (root 1.3.6.1.4.1.9.9.23.1.2.1.1.<col>),
// each row indexed by <cdpCacheIfIndex>.<cdpCacheDeviceIndex>. A switch/router
// populates this table from the CDP advertisements its directly-connected Cisco
// neighbors send, so walking it enumerates those neighbors. The address column
// gives a neighbor's IP directly (no separate table, unlike LLDP).
const (
	cdpCacheAddress    = "1.3.6.1.4.1.9.9.23.1.2.1.1.4" // neighbor's primary network address (IPv4 = 4 raw octets)
	cdpCacheVersion    = "1.3.6.1.4.1.9.9.23.1.2.1.1.5" // neighbor's software version banner
	cdpCacheDeviceID   = "1.3.6.1.4.1.9.9.23.1.2.1.1.6" // neighbor's device id / name
	cdpCacheDevicePort = "1.3.6.1.4.1.9.9.23.1.2.1.1.7" // neighbor's port facing the queried device
	cdpCachePlatform   = "1.3.6.1.4.1.9.9.23.1.2.1.1.8" // neighbor's hardware platform/model
)

// LLDP-MIB lldpRemTable columns (root 1.0.8802.1.1.2.1.4.1.1.<col>), each row
// indexed by <lldpRemTimeMark>.<lldpRemLocalPortNum>.<lldpRemIndex>. This is the
// vendor-neutral equivalent of the CDP cache: the device records one row per LLDP
// neighbor seen on each local port. The neighbor's IP is not here — it lives in
// the separate lldpRemManAddrTable, joined back by the same three-part index.
const (
	lldpRemChassisIDSubtype = "1.0.8802.1.1.2.1.4.1.1.4"  // how lldpRemChassisId is encoded (4 = macAddress)
	lldpRemChassisID        = "1.0.8802.1.1.2.1.4.1.1.5"  // neighbor chassis id (a MAC when the subtype is 4)
	lldpRemPortID           = "1.0.8802.1.1.2.1.4.1.1.7"  // neighbor's port identifier
	lldpRemPortDesc         = "1.0.8802.1.1.2.1.4.1.1.8"  // neighbor's port description
	lldpRemSysName          = "1.0.8802.1.1.2.1.4.1.1.9"  // neighbor's system name
	lldpRemSysDesc          = "1.0.8802.1.1.2.1.4.1.1.10" // neighbor's system description

	// lldpRemManAddrIfId is one column of lldpRemManAddrTable. The neighbor's
	// management address is encoded entirely in the row INDEX
	// (…4.2.1.<col>.<timeMark>.<localPort>.<remIndex>.<addrSubtype>.<addrLen>.<addr…>),
	// so walking any column of the table recovers the addresses; we pick this one
	// and read the IP out of each OID rather than its value.
	lldpRemManAddrIfId = "1.0.8802.1.1.2.1.4.2.1.4"

	// lldpChassisSubtypeMAC is the lldpRemChassisIdSubtype enum value meaning the
	// chassis id is a 6-byte MAC address (IEEE 802 macAddress).
	lldpChassisSubtypeMAC = 4

	// addrFamilyIPv4 is the IANA address-family number for IPv4, the
	// lldpRemManAddrSubtype value whose management address we decode.
	addrFamilyIPv4 = "1"
)

// neighbor is one decoded link-layer neighbor of a queried device, gathered from
// either the CDP cache or the LLDP remote table. Only neighbors that expose a
// management IP are usable for IPAM; the rest are dropped (we have nothing to key
// an observation on).
type neighbor struct {
	ip         string
	mac        string // from an LLDP MAC-typed chassis id, when present
	hostname   string // CDP device id or LLDP system name
	osDetail   string // CDP platform/version or LLDP system description
	osFamily   string // coarse guess from the OS detail
	source     string // "cdp" or "lldp"
	remotePort string // the neighbor's port facing the queried device
	platform   string // CDP hardware platform string (evidence)
	version    string // CDP/LLDP software version banner (evidence)
}

// observation turns a neighbor into a scan observation. The neighbor relationship
// (which device reported it, over which protocol, and the remote port) rides as
// evidence so an operator can see the topology behind the record.
func (n neighbor) observation(now time.Time, target string) scanner.Observation {
	obs := scanner.Observation{
		IP:         n.ip,
		MAC:        n.mac,
		Hostname:   n.hostname,
		OSDetail:   n.osDetail,
		OSFamily:   n.osFamily,
		ObservedAt: now,
	}
	proto := strings.ToUpper(n.source)
	ev := []scanner.Evidence{{Source: n.source, Summary: fmt.Sprintf("%s neighbor reported by %s", proto, target)}}
	if n.remotePort != "" {
		ev = append(ev, scanner.Evidence{Source: n.source, Summary: "Remote port: " + n.remotePort})
	}
	if n.platform != "" {
		ev = append(ev, scanner.Evidence{Source: n.source, Summary: "Platform: " + n.platform})
	}
	if n.version != "" {
		ev = append(ev, scanner.Evidence{Source: n.source, Summary: "Version", Raw: n.version})
	}
	obs.Evidence = ev
	return obs
}

// discoverNeighbors handles the lldp_cdp scan type: it asks each target device
// for the link-layer neighbors it sees (CDP + LLDP) and returns one observation
// per in-scope neighbor. A device that cannot be reached over SNMP contributes a
// per-target ScanError but does not fail the job; CDP and LLDP findings for the
// same neighbor (and the same neighbor seen via two targets) are merged by IP.
func (d *SNMPDiscoverer) discoverNeighbors(ctx context.Context, job scanner.ScanJob, scope []netip.Prefix, now time.Time) ([]scanner.Observation, []scanner.ScanError, error) {
	raw := make([]scanner.Observation, 0)
	scanErrs := make([]scanner.ScanError, 0)

	for _, target := range job.Targets {
		select {
		case <-ctx.Done():
			return mergeObservations(raw), scanErrs, ctx.Err()
		default:
		}

		neighbors, err := d.walkNeighbors(target)
		if err != nil {
			scanErrs = append(scanErrs, scanner.ScanError{
				Code:    "snmp_failed",
				Message: err.Error(),
				Target:  target,
			})
			continue
		}

		for _, n := range neighbors {
			addr, err := netip.ParseAddr(n.ip)
			if err != nil || !addr.Is4() || !withinScope(addr, scope) {
				continue
			}
			raw = append(raw, n.observation(now, target))
		}
	}

	// mergeObservations folds CDP+LLDP sightings of one neighbor (and the same
	// neighbor learned from two switches) into a single record, keyed by IP.
	return mergeObservations(raw), scanErrs, nil
}

// walkNeighbors connects to one device and reads both its CDP cache and its LLDP
// remote table. Each is best-effort: a device that speaks only one protocol (or
// neither) simply contributes fewer neighbors. The walk is treated as a failure
// only when no table could be read at all (the device is not answering SNMP) and
// nothing was learned — a device that answers but has no neighbors is a clean
// empty result, not an error.
func (d *SNMPDiscoverer) walkNeighbors(target string) ([]neighbor, error) {
	session, err := d.dial(target, d.cfg)
	if err != nil {
		return nil, fmt.Errorf("snmp dial %s: %w", target, err)
	}
	if err := session.Connect(); err != nil {
		return nil, fmt.Errorf("snmp connect %s: %w", target, err)
	}
	defer session.Close()

	var firstErr error
	anyOK := false

	cdp, err := collectCDP(session)
	if err != nil {
		if firstErr == nil {
			firstErr = err
		}
	} else {
		anyOK = true
	}

	lldp, err := collectLLDP(session)
	if err != nil {
		if firstErr == nil {
			firstErr = err
		}
	} else {
		anyOK = true
	}

	neighbors := append(cdp, lldp...)
	if len(neighbors) == 0 && !anyOK {
		return nil, fmt.Errorf("snmp neighbor walk %s: %w", target, firstErr)
	}
	return neighbors, nil
}

// collectCDP walks the CDP cache and returns one neighbor per cache entry. The
// address column anchors the set (a neighbor with no decodable IPv4 address is
// skipped); the remaining columns enrich it, joined by the two-part cache index.
func collectCDP(session snmpSession) ([]neighbor, error) {
	addrPDUs, err := session.BulkWalkAll(cdpCacheAddress)
	if err != nil {
		return nil, err
	}

	byIndex := make(map[string]*neighbor)
	order := make([]string, 0, len(addrPDUs))
	for _, pdu := range addrPDUs {
		idx, ok := cdpCacheIndex(pdu.Name)
		if !ok {
			continue
		}
		ip, ok := ipv4FromOctetValue(pdu.Value)
		if !ok {
			continue
		}
		if _, exists := byIndex[idx]; exists {
			continue
		}
		byIndex[idx] = &neighbor{ip: ip, source: "cdp"}
		order = append(order, idx)
	}

	enrich := func(colOID string, set func(n *neighbor, value string)) {
		pdus, err := session.BulkWalkAll(colOID)
		if err != nil {
			return
		}
		for _, pdu := range pdus {
			idx, ok := indexAfter(pdu.Name, colOID, 2)
			if !ok {
				continue
			}
			if n := byIndex[idx]; n != nil {
				if value := singleLine(octetString(pdu)); value != "" {
					set(n, value)
				}
			}
		}
	}
	enrich(cdpCacheDeviceID, func(n *neighbor, v string) { n.hostname = v })
	enrich(cdpCacheDevicePort, func(n *neighbor, v string) { n.remotePort = v })
	enrich(cdpCachePlatform, func(n *neighbor, v string) { n.platform = v })
	enrich(cdpCacheVersion, func(n *neighbor, v string) { n.version = v })

	out := make([]neighbor, 0, len(order))
	for _, idx := range order {
		n := byIndex[idx]
		// Platform is the hardware model (e.g. "cisco WS-C2960"); the version banner
		// carries the OS string. Surface the model as the OS detail and guess the
		// family from both.
		if n.osDetail == "" {
			n.osDetail = n.platform
		}
		n.osFamily = classifyOSFamily(n.version + " " + n.platform)
		out = append(out, *n)
	}
	return out, nil
}

// collectLLDP walks the LLDP remote table and returns one neighbor per management
// address. Unlike CDP, the neighbor's IP is not a column value but is encoded in
// the lldpRemManAddrTable row index, so that table anchors the set; the rest of
// the neighbor's facts come from lldpRemTable, joined by the shared three-part
// index. Neighbors with no management address are dropped (nothing to key on).
func collectLLDP(session snmpSession) ([]neighbor, error) {
	manPDUs, err := session.BulkWalkAll(lldpRemManAddrIfId)
	if err != nil {
		return nil, err
	}

	byKey := make(map[string]*neighbor)
	order := make([]string, 0, len(manPDUs))
	for _, pdu := range manPDUs {
		key, ip, ok := parseLLDPManAddr(pdu.Name)
		if !ok {
			continue
		}
		if _, exists := byKey[key]; exists {
			continue // keep the first management address per neighbor
		}
		byKey[key] = &neighbor{ip: ip, source: "lldp"}
		order = append(order, key)
	}
	if len(byKey) == 0 {
		// The device answered (no walk error) but advertises no LLDP neighbor with
		// a management address: a clean empty result, not a failure.
		return nil, nil
	}

	walkInto := func(colOID string, set func(n *neighbor, value string)) {
		pdus, err := session.BulkWalkAll(colOID)
		if err != nil {
			return
		}
		for _, pdu := range pdus {
			key, ok := indexAfter(pdu.Name, colOID, 3)
			if !ok {
				continue
			}
			if n := byKey[key]; n != nil {
				if value := singleLine(octetString(pdu)); value != "" {
					set(n, value)
				}
			}
		}
	}
	walkInto(lldpRemSysName, func(n *neighbor, v string) { n.hostname = v })
	walkInto(lldpRemSysDesc, func(n *neighbor, v string) { n.osDetail = v })
	walkInto(lldpRemPortID, func(n *neighbor, v string) { n.remotePort = v })
	// Port description is friendlier than the raw port id; let it win when present.
	walkInto(lldpRemPortDesc, func(n *neighbor, v string) { n.remotePort = v })

	// Chassis id is a MAC only when its subtype says so, so read the subtype map
	// first, then decode the matching chassis ids into MACs.
	subtypes := make(map[string]int)
	if pdus, err := session.BulkWalkAll(lldpRemChassisIDSubtype); err == nil {
		for _, pdu := range pdus {
			if key, ok := indexAfter(pdu.Name, lldpRemChassisIDSubtype, 3); ok {
				if st, ok := intFromPDU(pdu); ok {
					subtypes[key] = st
				}
			}
		}
	}
	if pdus, err := session.BulkWalkAll(lldpRemChassisID); err == nil {
		for _, pdu := range pdus {
			key, ok := indexAfter(pdu.Name, lldpRemChassisID, 3)
			if !ok {
				continue
			}
			if n := byKey[key]; n != nil && subtypes[key] == lldpChassisSubtypeMAC {
				if mac, ok := macFromPDU(pdu); ok {
					n.mac = mac
				}
			}
		}
	}

	out := make([]neighbor, 0, len(order))
	for _, key := range order {
		n := byKey[key]
		n.osFamily = classifyOSFamily(n.osDetail)
		out = append(out, *n)
	}
	return out, nil
}

// cdpCacheIndex returns the two-part <ifIndex>.<deviceIndex> index of a
// cdpCacheAddress row OID, the join key across the CDP cache columns.
func cdpCacheIndex(oid string) (string, bool) {
	return indexAfter(oid, cdpCacheAddress, 2)
}

// indexAfter strips a table column's OID prefix from a row OID and returns the
// remaining index sub-identifiers, requiring exactly want of them. The trailing
// dot in the prefix means a ".4" column never matches a ".40" column's rows.
func indexAfter(oid, colOID string, want int) (string, bool) {
	suffix, ok := oidSuffix(oid, colOID)
	if !ok {
		return "", false
	}
	if strings.Count(suffix, ".")+1 != want {
		return "", false
	}
	return suffix, true
}

// oidSuffix returns the portion of oid following colOID's prefix (with a
// separating dot), normalized so an absolute (".1.3…") and relative ("1.3…") OID
// compare the same. ok is false when oid is not under colOID.
func oidSuffix(oid, colOID string) (string, bool) {
	n := normalizeOID(oid)
	prefix := normalizeOID(colOID) + "."
	if !strings.HasPrefix(n, prefix) {
		return "", false
	}
	return strings.TrimPrefix(n, prefix), true
}

// parseLLDPManAddr decodes an lldpRemManAddrTable row OID. The index after the
// column is <timeMark>.<localPort>.<remIndex>.<addrSubtype>.<addrLen>.<addr…>;
// the first three parts are the join key back to lldpRemTable, and an IPv4
// management address (subtype 1, length 4) is read from the trailing octets. A
// non-IPv4 family is reported as not-ok and skipped.
func parseLLDPManAddr(oid string) (key, ip string, ok bool) {
	suffix, ok := oidSuffix(oid, lldpRemManAddrIfId)
	if !ok {
		return "", "", false
	}
	parts := strings.Split(suffix, ".")
	// timeMark, localPort, remIndex, addrSubtype, addrLen, then the address bytes.
	if len(parts) < 5 {
		return "", "", false
	}
	if parts[3] != addrFamilyIPv4 || parts[4] != "4" || len(parts) < 9 {
		return "", "", false
	}
	var octets [4]byte
	for i, p := range parts[5:9] {
		v, err := strconv.Atoi(p)
		if err != nil || v < 0 || v > 255 {
			return "", "", false
		}
		octets[i] = byte(v)
	}
	return strings.Join(parts[0:3], "."), netip.AddrFrom4(octets).String(), true
}

// ipv4FromOctetValue decodes a 4-byte SNMP OctetString value (as CDP stores a
// neighbor's IPv4 address in cdpCacheAddress) into dotted-quad form.
func ipv4FromOctetValue(v any) (string, bool) {
	raw, ok := v.([]byte)
	if !ok || len(raw) != 4 {
		return "", false
	}
	return netip.AddrFrom4([4]byte{raw[0], raw[1], raw[2], raw[3]}).String(), true
}
