package agent

import (
	"context"
	"errors"
	"testing"

	"github.com/devSealWare/LightIPAM/internal/scanner"
	"github.com/gosnmp/gosnmp"
)

// --- lldp_cdp test PDU builders ---

func cdpAddrPDU(ifIndex, devIndex int, ip [4]int) gosnmp.SnmpPDU {
	name := cdpCacheAddress + "." + itoa(ifIndex) + "." + itoa(devIndex)
	return gosnmp.SnmpPDU{Name: name, Type: gosnmp.OctetString,
		Value: []byte{byte(ip[0]), byte(ip[1]), byte(ip[2]), byte(ip[3])}}
}

func cdpStrPDU(col string, ifIndex, devIndex int, value string) gosnmp.SnmpPDU {
	name := col + "." + itoa(ifIndex) + "." + itoa(devIndex)
	return gosnmp.SnmpPDU{Name: name, Type: gosnmp.OctetString, Value: []byte(value)}
}

func lldpManAddrPDU(timeMark, localPort, remIndex int, subtype, length int, addr []int) gosnmp.SnmpPDU {
	name := lldpRemManAddrIfId + "." + itoa(timeMark) + "." + itoa(localPort) + "." + itoa(remIndex) +
		"." + itoa(subtype) + "." + itoa(length)
	for _, a := range addr {
		name += "." + itoa(a)
	}
	return gosnmp.SnmpPDU{Name: name, Type: gosnmp.Integer, Value: 1}
}

func lldpRemPDU(col string, timeMark, localPort, remIndex int, value any, typ gosnmp.Asn1BER) gosnmp.SnmpPDU {
	name := col + "." + itoa(timeMark) + "." + itoa(localPort) + "." + itoa(remIndex)
	return gosnmp.SnmpPDU{Name: name, Type: typ, Value: value}
}

func neighborJob(targets, allowed []string) scanner.ScanJob {
	job := newJob(targets, allowed)
	job.Type = scanner.ScanLLDPCDP
	return job
}

func TestNeighborDiscoverCDP(t *testing.T) {
	session := &fakeSNMPSession{walks: map[string][]gosnmp.SnmpPDU{
		cdpCacheAddress: {
			cdpAddrPDU(2, 1, [4]int{192, 168, 0, 50}),
			cdpAddrPDU(3, 1, [4]int{10, 0, 0, 5}), // out of allowlist scope — dropped
		},
		cdpCacheDeviceID:   {cdpStrPDU(cdpCacheDeviceID, 2, 1, "ap1")},
		cdpCacheDevicePort: {cdpStrPDU(cdpCacheDevicePort, 2, 1, "GigabitEthernet0/1")},
		cdpCachePlatform:   {cdpStrPDU(cdpCachePlatform, 2, 1, "cisco AIR-AP1815")},
		cdpCacheVersion:    {cdpStrPDU(cdpCacheVersion, 2, 1, "Cisco IOS Software, C1140")},
	}}
	d := NewSNMPDiscoverer(SNMPConfig{})
	d.dial = func(target string, cfg SNMPConfig) (snmpSession, error) { return session, nil }

	obs, scanErrs, err := d.Discover(context.Background(), neighborJob(
		[]string{"192.168.0.1"}, []string{"192.168.0.0/24"}))
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if len(scanErrs) != 0 {
		t.Fatalf("unexpected scan errors: %+v", scanErrs)
	}
	if !session.closed {
		t.Errorf("session was not closed")
	}
	if len(obs) != 1 {
		t.Fatalf("got %d observations, want 1 (in-scope CDP neighbor): %+v", len(obs), obs)
	}
	o := obs[0]
	if o.IP != "192.168.0.50" {
		t.Errorf("IP = %s, want 192.168.0.50", o.IP)
	}
	if o.Hostname != "ap1" {
		t.Errorf("Hostname = %s, want ap1", o.Hostname)
	}
	if o.OSDetail != "cisco AIR-AP1815" {
		t.Errorf("OSDetail = %s, want the platform string", o.OSDetail)
	}
	if o.OSFamily != "Cisco IOS" {
		t.Errorf("OSFamily = %s, want Cisco IOS (from version banner)", o.OSFamily)
	}
	if !hasEvidence(o.Evidence, "Remote port: GigabitEthernet0/1") {
		t.Errorf("missing remote-port evidence: %+v", o.Evidence)
	}
	if !hasEvidence(o.Evidence, "Platform: cisco AIR-AP1815") {
		t.Errorf("missing platform evidence: %+v", o.Evidence)
	}
	if len(o.Evidence) == 0 || o.Evidence[0].Source != "cdp" {
		t.Errorf("expected cdp-sourced evidence, got %+v", o.Evidence)
	}
}

func TestNeighborDiscoverLLDP(t *testing.T) {
	session := &fakeSNMPSession{walks: map[string][]gosnmp.SnmpPDU{
		lldpRemManAddrIfId: {
			lldpManAddrPDU(100, 5, 1, 1, 4, []int{192, 168, 0, 60}), // IPv4
			lldpManAddrPDU(100, 6, 2, 2, 16, []int{0x20, 0x01}),     // IPv6 family — skipped
		},
		lldpRemSysName:          {lldpRemPDU(lldpRemSysName, 100, 5, 1, []byte("printer"), gosnmp.OctetString)},
		lldpRemSysDesc:          {lldpRemPDU(lldpRemSysDesc, 100, 5, 1, []byte("HP LaserJet 400"), gosnmp.OctetString)},
		lldpRemPortDesc:         {lldpRemPDU(lldpRemPortDesc, 100, 5, 1, []byte("Port 5"), gosnmp.OctetString)},
		lldpRemChassisIDSubtype: {lldpRemPDU(lldpRemChassisIDSubtype, 100, 5, 1, lldpChassisSubtypeMAC, gosnmp.Integer)},
		lldpRemChassisID:        {lldpRemPDU(lldpRemChassisID, 100, 5, 1, []byte{0xaa, 0xbb, 0xcc, 0x00, 0x11, 0x22}, gosnmp.OctetString)},
	}}
	d := NewSNMPDiscoverer(SNMPConfig{})
	d.dial = func(target string, cfg SNMPConfig) (snmpSession, error) { return session, nil }

	obs, scanErrs, err := d.Discover(context.Background(), neighborJob(
		[]string{"192.168.0.1"}, []string{"192.168.0.0/24"}))
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if len(scanErrs) != 0 {
		t.Fatalf("unexpected scan errors: %+v", scanErrs)
	}
	if len(obs) != 1 {
		t.Fatalf("got %d observations, want 1 (only the IPv4 LLDP neighbor): %+v", len(obs), obs)
	}
	o := obs[0]
	if o.IP != "192.168.0.60" {
		t.Errorf("IP = %s, want 192.168.0.60", o.IP)
	}
	if o.MAC != "aa:bb:cc:00:11:22" {
		t.Errorf("MAC = %s, want the MAC-typed chassis id", o.MAC)
	}
	if o.Hostname != "printer" {
		t.Errorf("Hostname = %s, want printer", o.Hostname)
	}
	if o.OSDetail != "HP LaserJet 400" {
		t.Errorf("OSDetail = %s, want the system description", o.OSDetail)
	}
	if !hasEvidence(o.Evidence, "Remote port: Port 5") {
		t.Errorf("missing remote-port evidence: %+v", o.Evidence)
	}
	if len(o.Evidence) == 0 || o.Evidence[0].Source != "lldp" {
		t.Errorf("expected lldp-sourced evidence, got %+v", o.Evidence)
	}
}

func TestNeighborDiscoverMergesCDPandLLDP(t *testing.T) {
	// The same neighbor IP is seen via CDP (which carries the name/platform) and
	// LLDP (which carries the chassis MAC); the two must merge onto one record.
	session := &fakeSNMPSession{walks: map[string][]gosnmp.SnmpPDU{
		cdpCacheAddress:  {cdpAddrPDU(2, 1, [4]int{192, 168, 0, 70})},
		cdpCacheDeviceID: {cdpStrPDU(cdpCacheDeviceID, 2, 1, "sw2")},
		cdpCachePlatform: {cdpStrPDU(cdpCachePlatform, 2, 1, "cisco WS-C2960")},

		lldpRemManAddrIfId:      {lldpManAddrPDU(100, 5, 1, 1, 4, []int{192, 168, 0, 70})},
		lldpRemChassisIDSubtype: {lldpRemPDU(lldpRemChassisIDSubtype, 100, 5, 1, lldpChassisSubtypeMAC, gosnmp.Integer)},
		lldpRemChassisID:        {lldpRemPDU(lldpRemChassisID, 100, 5, 1, []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}, gosnmp.OctetString)},
	}}
	d := NewSNMPDiscoverer(SNMPConfig{})
	d.dial = func(target string, cfg SNMPConfig) (snmpSession, error) { return session, nil }

	obs, _, err := d.Discover(context.Background(), neighborJob(
		[]string{"192.168.0.1"}, []string{"192.168.0.0/24"}))
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if len(obs) != 1 {
		t.Fatalf("got %d observations, want 1 (CDP+LLDP merged by IP): %+v", len(obs), obs)
	}
	o := obs[0]
	if o.Hostname != "sw2" {
		t.Errorf("Hostname = %s, want sw2 (CDP leads)", o.Hostname)
	}
	if o.MAC != "00:11:22:33:44:55" {
		t.Errorf("MAC = %s, want the LLDP chassis MAC merged in", o.MAC)
	}
	// Evidence from both protocols should be present.
	if !hasEvidence(o.Evidence, "Platform: cisco WS-C2960") {
		t.Errorf("missing CDP platform evidence: %+v", o.Evidence)
	}
}

func TestNeighborDiscoverReachableNoNeighbors(t *testing.T) {
	// A switch that answers SNMP but advertises no CDP/LLDP neighbors is a clean
	// empty result, not a per-target failure.
	session := &fakeSNMPSession{walks: map[string][]gosnmp.SnmpPDU{}}
	d := NewSNMPDiscoverer(SNMPConfig{})
	d.dial = func(target string, cfg SNMPConfig) (snmpSession, error) { return session, nil }

	obs, scanErrs, err := d.Discover(context.Background(), neighborJob(
		[]string{"192.168.0.1"}, []string{"192.168.0.0/24"}))
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if len(obs) != 0 {
		t.Fatalf("got %d observations, want 0: %+v", len(obs), obs)
	}
	if len(scanErrs) != 0 {
		t.Fatalf("a reachable switch with no neighbors must not error: %+v", scanErrs)
	}
}

func TestNeighborDiscoverPerTargetError(t *testing.T) {
	d := NewSNMPDiscoverer(SNMPConfig{})
	d.dial = func(target string, cfg SNMPConfig) (snmpSession, error) {
		if target == "192.168.0.1" {
			return &fakeSNMPSession{walks: map[string][]gosnmp.SnmpPDU{
				cdpCacheAddress:  {cdpAddrPDU(2, 1, [4]int{192, 168, 0, 50})},
				cdpCacheDeviceID: {cdpStrPDU(cdpCacheDeviceID, 2, 1, "ap1")},
			}}, nil
		}
		// A device that answers no table at all fails just this target.
		return &fakeSNMPSession{walkErr: errors.New("request timeout")}, nil
	}

	obs, scanErrs, err := d.Discover(context.Background(), neighborJob(
		[]string{"192.168.0.1", "192.168.0.2"}, []string{"192.168.0.0/24"}))
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if len(obs) != 1 {
		t.Fatalf("got %d observations, want 1: %+v", len(obs), obs)
	}
	if len(scanErrs) != 1 || scanErrs[0].Code != "snmp_failed" || scanErrs[0].Target != "192.168.0.2" {
		t.Fatalf("scan errors = %+v", scanErrs)
	}
}

func TestParseLLDPManAddr(t *testing.T) {
	tests := []struct {
		name    string
		oid     string
		wantKey string
		wantIP  string
		ok      bool
	}{
		{"ipv4", lldpRemManAddrIfId + ".100.5.1.1.4.192.168.0.60", "100.5.1", "192.168.0.60", true},
		{"absolute oid", "." + lldpRemManAddrIfId + ".7.2.3.1.4.10.0.0.9", "7.2.3", "10.0.0.9", true},
		{"ipv6 family", lldpRemManAddrIfId + ".100.5.1.2.16.32.1.13.184.0.0.0.0.0.0.0.0.0.0.0.1", "", "", false},
		{"truncated", lldpRemManAddrIfId + ".100.5.1.1.4.192.168", "", "", false},
		{"wrong column", cdpCacheAddress + ".100.5.1.1.4.192.168.0.60", "", "", false},
	}
	for _, tt := range tests {
		key, ip, ok := parseLLDPManAddr(tt.oid)
		if ok != tt.ok || key != tt.wantKey || ip != tt.wantIP {
			t.Errorf("%s: parseLLDPManAddr(%q) = %q,%q,%v; want %q,%q,%v",
				tt.name, tt.oid, key, ip, ok, tt.wantKey, tt.wantIP, tt.ok)
		}
	}
}

func TestCDPCacheIndex(t *testing.T) {
	tests := []struct {
		oid  string
		want string
		ok   bool
	}{
		{cdpCacheAddress + ".2.1", "2.1", true},
		{"." + cdpCacheAddress + ".10.3", "10.3", true},
		{cdpCacheAddress + ".2", "", false},     // too few index parts
		{cdpCacheAddress + ".2.1.9", "", false}, // too many index parts
		{lldpRemSysName + ".2.1", "", false},    // wrong column
	}
	for _, tt := range tests {
		got, ok := cdpCacheIndex(tt.oid)
		if ok != tt.ok || got != tt.want {
			t.Errorf("cdpCacheIndex(%q) = %q,%v; want %q,%v", tt.oid, got, ok, tt.want, tt.ok)
		}
	}
}

func TestIPv4FromOctetValue(t *testing.T) {
	if got, ok := ipv4FromOctetValue([]byte{192, 168, 1, 9}); !ok || got != "192.168.1.9" {
		t.Errorf("ipv4FromOctetValue(4 bytes) = %q,%v", got, ok)
	}
	if _, ok := ipv4FromOctetValue([]byte{192, 168, 1}); ok {
		t.Errorf("ipv4FromOctetValue(3 bytes) should fail")
	}
	if _, ok := ipv4FromOctetValue("192.168.1.9"); ok {
		t.Errorf("ipv4FromOctetValue(string) should fail")
	}
}
