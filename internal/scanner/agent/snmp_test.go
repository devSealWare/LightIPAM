package agent

import (
	"context"
	"errors"
	"testing"

	"github.com/devSealWare/LightIPAM/internal/scanner"
	"github.com/gosnmp/gosnmp"
)

// fakeSNMPSession returns canned PDUs (or an error) instead of touching a device.
// BulkWalkAll consults walks (keyed by root OID) when set, otherwise falls back to
// pdus; Get returns getPDUs/getErr.
type fakeSNMPSession struct {
	pdus     []gosnmp.SnmpPDU
	walks    map[string][]gosnmp.SnmpPDU
	getPDUs  []gosnmp.SnmpPDU
	getErr   error
	walkErr  error
	connErr  error
	closed   bool
	walkRoot string
}

func (f *fakeSNMPSession) Connect() error { return f.connErr }

func (f *fakeSNMPSession) Get(oids []string) (*gosnmp.SnmpPacket, error) {
	if f.getErr != nil {
		return nil, f.getErr
	}
	return &gosnmp.SnmpPacket{Variables: f.getPDUs}, nil
}

func (f *fakeSNMPSession) BulkWalkAll(rootOID string) ([]gosnmp.SnmpPDU, error) {
	f.walkRoot = rootOID
	if f.walkErr != nil {
		return nil, f.walkErr
	}
	if f.walks != nil {
		return f.walks[rootOID], nil
	}
	return f.pdus, nil
}

func (f *fakeSNMPSession) Close() error {
	f.closed = true
	return nil
}

func arpPDU(ifIndex int, ip [4]int, mac []byte) gosnmp.SnmpPDU {
	name := ipNetToMediaPhysAddress
	name += "." + itoa(ifIndex)
	for _, o := range ip {
		name += "." + itoa(o)
	}
	return gosnmp.SnmpPDU{Name: name, Type: gosnmp.OctetString, Value: mac}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

func newJob(targets, allowed []string) scanner.ScanJob {
	return scanner.ScanJob{
		ID:           "job-1",
		AgentID:      "agent-1",
		Type:         scanner.ScanARPTable,
		Mode:         scanner.ModeLightActive,
		AllowedCIDRs: allowed,
		Targets:      targets,
	}
}

func TestSNMPDiscoverDecodesAndFilters(t *testing.T) {
	pdus := []gosnmp.SnmpPDU{
		arpPDU(2, [4]int{192, 168, 0, 10}, []byte{0xaa, 0xbb, 0xcc, 0x00, 0x11, 0x22}),
		arpPDU(2, [4]int{192, 168, 0, 11}, []byte{0xde, 0xad, 0xbe, 0xef, 0x00, 0x01}),
		// Out of allowlist scope — must be dropped.
		arpPDU(2, [4]int{10, 0, 0, 5}, []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}),
		// All-zero (incomplete) MAC — must be skipped.
		arpPDU(2, [4]int{192, 168, 0, 12}, []byte{0, 0, 0, 0, 0, 0}),
	}
	session := &fakeSNMPSession{pdus: pdus}
	d := NewSNMPDiscoverer(SNMPConfig{})
	d.dial = func(target string, cfg SNMPConfig) (snmpSession, error) { return session, nil }

	obs, scanErrs, err := d.Discover(context.Background(), newJob(
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
	if session.walkRoot != ipNetToMediaPhysAddress {
		t.Errorf("walked %q, want %q", session.walkRoot, ipNetToMediaPhysAddress)
	}
	if len(obs) != 2 {
		t.Fatalf("got %d observations, want 2: %+v", len(obs), obs)
	}
	if obs[0].IP != "192.168.0.10" || obs[0].MAC != "aa:bb:cc:00:11:22" {
		t.Errorf("obs[0] = %s / %s", obs[0].IP, obs[0].MAC)
	}
	if obs[1].IP != "192.168.0.11" || obs[1].MAC != "de:ad:be:ef:00:01" {
		t.Errorf("obs[1] = %s / %s", obs[1].IP, obs[1].MAC)
	}
	if len(obs[0].Evidence) != 1 || obs[0].Evidence[0].Source != "snmp" {
		t.Errorf("expected snmp evidence, got %+v", obs[0].Evidence)
	}
	if obs[0].ObservedAt.IsZero() {
		t.Errorf("ObservedAt not set")
	}
}

func TestSNMPDiscoverDedupesAcrossGateways(t *testing.T) {
	makeSession := func() *fakeSNMPSession {
		return &fakeSNMPSession{pdus: []gosnmp.SnmpPDU{
			arpPDU(2, [4]int{192, 168, 0, 10}, []byte{0xaa, 0xbb, 0xcc, 0x00, 0x11, 0x22}),
		}}
	}
	d := NewSNMPDiscoverer(SNMPConfig{})
	d.dial = func(target string, cfg SNMPConfig) (snmpSession, error) { return makeSession(), nil }

	obs, _, err := d.Discover(context.Background(), newJob(
		[]string{"192.168.0.1", "192.168.0.2"}, []string{"192.168.0.0/24"}))
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if len(obs) != 1 {
		t.Fatalf("got %d observations, want 1 (deduped): %+v", len(obs), obs)
	}
}

func TestSNMPDiscoverReportsPerTargetError(t *testing.T) {
	d := NewSNMPDiscoverer(SNMPConfig{})
	d.dial = func(target string, cfg SNMPConfig) (snmpSession, error) {
		if target == "192.168.0.1" {
			return &fakeSNMPSession{pdus: []gosnmp.SnmpPDU{
				arpPDU(2, [4]int{192, 168, 0, 10}, []byte{0xaa, 0xbb, 0xcc, 0x00, 0x11, 0x22}),
			}}, nil
		}
		return &fakeSNMPSession{walkErr: errors.New("request timeout")}, nil
	}

	obs, scanErrs, err := d.Discover(context.Background(), newJob(
		[]string{"192.168.0.1", "192.168.0.2"}, []string{"192.168.0.0/24"}))
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if len(obs) != 1 {
		t.Fatalf("got %d observations, want 1: %+v", len(obs), obs)
	}
	if len(scanErrs) != 1 {
		t.Fatalf("got %d scan errors, want 1: %+v", len(scanErrs), scanErrs)
	}
	if scanErrs[0].Code != "snmp_failed" || scanErrs[0].Target != "192.168.0.2" {
		t.Errorf("scan error = %+v", scanErrs[0])
	}
}

func TestSNMPDiscoverPassiveIsNoop(t *testing.T) {
	called := false
	d := NewSNMPDiscoverer(SNMPConfig{})
	d.dial = func(target string, cfg SNMPConfig) (snmpSession, error) {
		called = true
		return &fakeSNMPSession{}, nil
	}
	job := newJob([]string{"192.168.0.1"}, []string{"192.168.0.0/24"})
	job.Mode = scanner.ModePassive

	obs, scanErrs, err := d.Discover(context.Background(), job)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if called {
		t.Errorf("passive scan dialed the device")
	}
	if len(obs) != 0 || len(scanErrs) != 0 {
		t.Errorf("passive scan should report nothing, got %d obs / %d errs", len(obs), len(scanErrs))
	}
}

func TestSNMPConfigDefaults(t *testing.T) {
	d := NewSNMPDiscoverer(SNMPConfig{})
	if d.cfg.Version != SNMPv2c {
		t.Errorf("version = %q, want 2c", d.cfg.Version)
	}
	if d.cfg.Community != "public" {
		t.Errorf("community = %q, want public", d.cfg.Community)
	}
	if d.cfg.Port != 161 {
		t.Errorf("port = %d, want 161", d.cfg.Port)
	}
	if d.cfg.Timeout <= 0 {
		t.Errorf("timeout not defaulted: %v", d.cfg.Timeout)
	}
}

func TestIPFromARPOID(t *testing.T) {
	tests := []struct {
		oid  string
		want string
		ok   bool
	}{
		{ipNetToMediaPhysAddress + ".2.192.168.1.5", "192.168.1.5", true},
		{"." + ipNetToMediaPhysAddress + ".10.10.0.0.1", "10.0.0.1", true},
		{ipNetToMediaPhysAddress + ".2.192.168.1.300", "", false}, // octet > 255
		{"1.2.3", "", false}, // too few sub-identifiers
	}
	for _, tt := range tests {
		got, ok := ipFromARPOID(tt.oid)
		if ok != tt.ok || got != tt.want {
			t.Errorf("ipFromARPOID(%q) = %q,%v; want %q,%v", tt.oid, got, ok, tt.want, tt.ok)
		}
	}
}

func TestMACFromPDU(t *testing.T) {
	tests := []struct {
		name  string
		value any
		want  string
		ok    bool
	}{
		{"valid", []byte{0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e}, "00:1a:2b:3c:4d:5e", true},
		{"all zero", []byte{0, 0, 0, 0, 0, 0}, "", false},
		{"wrong length", []byte{0x00, 0x1a, 0x2b}, "", false},
		{"not bytes", "00:1a:2b:3c:4d:5e", "", false},
	}
	for _, tt := range tests {
		got, ok := macFromPDU(gosnmp.SnmpPDU{Value: tt.value})
		if ok != tt.ok || got != tt.want {
			t.Errorf("%s: macFromPDU = %q,%v; want %q,%v", tt.name, got, ok, tt.want, tt.ok)
		}
	}
}

// --- snmp_inventory ---

func ipAddrPDU(ip [4]int, ifIndex int) gosnmp.SnmpPDU {
	name := oidIPAdEntIfIndex
	for _, o := range ip {
		name += "." + itoa(o)
	}
	return gosnmp.SnmpPDU{Name: name, Type: gosnmp.Integer, Value: ifIndex}
}

func ifPhysPDU(ifIndex int, mac []byte) gosnmp.SnmpPDU {
	return gosnmp.SnmpPDU{Name: oidIfPhysAddress + "." + itoa(ifIndex), Type: gosnmp.OctetString, Value: mac}
}

func ifDescrPDU(ifIndex int, name string) gosnmp.SnmpPDU {
	return gosnmp.SnmpPDU{Name: oidIfDescr + "." + itoa(ifIndex), Type: gosnmp.OctetString, Value: []byte(name)}
}

func octet(oid, value string) gosnmp.SnmpPDU {
	return gosnmp.SnmpPDU{Name: oid, Type: gosnmp.OctetString, Value: []byte(value)}
}

func operStatusPDU(ifIndex, status int) gosnmp.SnmpPDU {
	return gosnmp.SnmpPDU{Name: oidIfOperStatus + "." + itoa(ifIndex), Type: gosnmp.Integer, Value: status}
}

func basePortIfIndexPDU(port, ifIndex int) gosnmp.SnmpPDU {
	return gosnmp.SnmpPDU{Name: oidDot1dBasePortIfIndex + "." + itoa(port), Type: gosnmp.Integer, Value: ifIndex}
}

func pvidPDU(port, vlan int) gosnmp.SnmpPDU {
	return gosnmp.SnmpPDU{Name: oidDot1qPvid + "." + itoa(port), Type: gosnmp.Gauge32, Value: uint(vlan)}
}

func vlanNamePDU(vlan int, name string) gosnmp.SnmpPDU {
	return gosnmp.SnmpPDU{Name: oidDot1qVlanStaticName + "." + itoa(vlan), Type: gosnmp.OctetString, Value: []byte(name)}
}

func inventoryJob(targets, allowed []string) scanner.ScanJob {
	job := newJob(targets, allowed)
	job.Type = scanner.ScanSNMPInventory
	return job
}

func hasEvidence(ev []scanner.Evidence, summary string) bool {
	for _, e := range ev {
		if e.Summary == summary {
			return true
		}
	}
	return false
}

func TestSNMPInventoryDecodesAndJoins(t *testing.T) {
	session := &fakeSNMPSession{
		getPDUs: []gosnmp.SnmpPDU{
			octet(oidSysDescr, "Linux router1 5.10.0 x86_64"),
			{Name: oidSysObjectID, Type: gosnmp.ObjectIdentifier, Value: ".1.3.6.1.4.1.8072.3.2.10"},
			{Name: oidSysUpTime, Type: gosnmp.TimeTicks, Value: uint32(8640000)}, // 24h in 1/100s
			octet(oidSysName, "router1"),
			octet(oidSysLocation, "Rack 3"),
		},
		walks: map[string][]gosnmp.SnmpPDU{
			oidIPAdEntIfIndex: {
				ipAddrPDU([4]int{192, 168, 0, 1}, 2),
				ipAddrPDU([4]int{10, 9, 9, 9}, 3),  // out of allowlist scope — dropped
				ipAddrPDU([4]int{127, 0, 0, 1}, 1), // loopback, out of scope — dropped
			},
			oidIfPhysAddress: {ifPhysPDU(2, []byte{0xaa, 0xbb, 0xcc, 0x00, 0x11, 0x22})},
			oidIfDescr:       {ifDescrPDU(2, "eth0")},
		},
	}
	d := NewSNMPDiscoverer(SNMPConfig{})
	d.dial = func(target string, cfg SNMPConfig) (snmpSession, error) { return session, nil }

	obs, scanErrs, err := d.Discover(context.Background(), inventoryJob(
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
		t.Fatalf("got %d observations, want 1 (in-scope owned IP): %+v", len(obs), obs)
	}
	o := obs[0]
	if o.IP != "192.168.0.1" {
		t.Errorf("IP = %s, want 192.168.0.1", o.IP)
	}
	if o.MAC != "aa:bb:cc:00:11:22" {
		t.Errorf("MAC = %s (interface join failed)", o.MAC)
	}
	if o.Hostname != "router1" {
		t.Errorf("Hostname = %s, want router1", o.Hostname)
	}
	if o.OSFamily != "Linux" {
		t.Errorf("OSFamily = %s, want Linux", o.OSFamily)
	}
	if o.OSDetail != "Linux router1 5.10.0 x86_64" {
		t.Errorf("OSDetail = %s", o.OSDetail)
	}
	if !hasEvidence(o.Evidence, "Interface eth0 (ifIndex 2)") {
		t.Errorf("missing interface evidence: %+v", o.Evidence)
	}
	if !hasEvidence(o.Evidence, "Uptime: 1d 0h 0m") {
		t.Errorf("missing uptime evidence: %+v", o.Evidence)
	}
	if !hasEvidence(o.Evidence, "Location: Rack 3") {
		t.Errorf("missing location evidence: %+v", o.Evidence)
	}
}

func TestSNMPInventoryMapsVLANAndOper(t *testing.T) {
	// 192.168.0.1 sits on ifIndex 2; bridge port 7 maps to ifIndex 2 and carries
	// PVID 20 ("Engineering"); ifIndex 2 is operationally up.
	session := &fakeSNMPSession{
		getPDUs: []gosnmp.SnmpPDU{octet(oidSysName, "switch1"), octet(oidSysDescr, "Cisco IOS")},
		walks: map[string][]gosnmp.SnmpPDU{
			oidIPAdEntIfIndex:       {ipAddrPDU([4]int{192, 168, 0, 1}, 2)},
			oidIfPhysAddress:        {ifPhysPDU(2, []byte{0xaa, 0xbb, 0xcc, 0x00, 0x11, 0x22})},
			oidIfDescr:              {ifDescrPDU(2, "Gi0/1")},
			oidIfOperStatus:         {operStatusPDU(2, 1), operStatusPDU(3, 2)},
			oidDot1dBasePortIfIndex: {basePortIfIndexPDU(7, 2)},
			oidDot1qPvid:            {pvidPDU(7, 20)},
			oidDot1qVlanStaticName:  {vlanNamePDU(20, "Engineering")},
		},
	}
	d := NewSNMPDiscoverer(SNMPConfig{})
	d.dial = func(target string, cfg SNMPConfig) (snmpSession, error) { return session, nil }

	obs, scanErrs, err := d.Discover(context.Background(), inventoryJob(
		[]string{"192.168.0.1"}, []string{"192.168.0.0/24"}))
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if len(scanErrs) != 0 {
		t.Fatalf("unexpected scan errors: %+v", scanErrs)
	}
	if len(obs) != 1 {
		t.Fatalf("got %d observations, want 1: %+v", len(obs), obs)
	}
	o := obs[0]
	if o.VLAN != 20 {
		t.Errorf("VLAN = %d, want 20 (joined through bridge port)", o.VLAN)
	}
	if !hasEvidence(o.Evidence, "Interface Gi0/1 (ifIndex 2), up") {
		t.Errorf("missing interface+oper evidence: %+v", o.Evidence)
	}
	if !hasEvidence(o.Evidence, "VLAN 20 (Engineering)") {
		t.Errorf("missing VLAN evidence: %+v", o.Evidence)
	}
}

func TestSNMPInventoryTargetFallback(t *testing.T) {
	// The device answers the system Get but exposes no in-scope ipAddrTable
	// address; the in-scope target IP itself records the device.
	session := &fakeSNMPSession{
		getPDUs: []gosnmp.SnmpPDU{
			octet(oidSysName, "switch1"),
			octet(oidSysDescr, "Cisco IOS Software, C2960"),
		},
		walks: map[string][]gosnmp.SnmpPDU{
			oidIPAdEntIfIndex: {ipAddrPDU([4]int{10, 0, 0, 5}, 2)}, // out of scope
		},
	}
	d := NewSNMPDiscoverer(SNMPConfig{})
	d.dial = func(target string, cfg SNMPConfig) (snmpSession, error) { return session, nil }

	obs, _, err := d.Discover(context.Background(), inventoryJob(
		[]string{"192.168.0.1"}, []string{"192.168.0.0/24"}))
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if len(obs) != 1 {
		t.Fatalf("got %d observations, want 1 fallback: %+v", len(obs), obs)
	}
	if obs[0].IP != "192.168.0.1" || obs[0].Hostname != "switch1" {
		t.Errorf("fallback obs = %+v", obs[0])
	}
	if obs[0].MAC != "" {
		t.Errorf("fallback MAC should be empty (interface unknown), got %s", obs[0].MAC)
	}
	if obs[0].OSFamily != "Cisco IOS" {
		t.Errorf("OSFamily = %s, want Cisco IOS", obs[0].OSFamily)
	}
}

func TestSNMPInventoryDedupesAcrossTargets(t *testing.T) {
	makeSession := func() *fakeSNMPSession {
		return &fakeSNMPSession{
			getPDUs: []gosnmp.SnmpPDU{octet(oidSysName, "dev")},
			walks: map[string][]gosnmp.SnmpPDU{
				oidIPAdEntIfIndex: {ipAddrPDU([4]int{192, 168, 0, 1}, 2)},
			},
		}
	}
	d := NewSNMPDiscoverer(SNMPConfig{})
	d.dial = func(target string, cfg SNMPConfig) (snmpSession, error) { return makeSession(), nil }

	obs, _, err := d.Discover(context.Background(), inventoryJob(
		[]string{"192.168.0.1", "192.168.0.2"}, []string{"192.168.0.0/24"}))
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if len(obs) != 1 {
		t.Fatalf("got %d observations, want 1 (deduped by IP): %+v", len(obs), obs)
	}
}

func TestSNMPInventoryPerTargetError(t *testing.T) {
	d := NewSNMPDiscoverer(SNMPConfig{})
	d.dial = func(target string, cfg SNMPConfig) (snmpSession, error) {
		if target == "192.168.0.1" {
			return &fakeSNMPSession{
				getPDUs: []gosnmp.SnmpPDU{octet(oidSysName, "ok")},
				walks:   map[string][]gosnmp.SnmpPDU{oidIPAdEntIfIndex: {ipAddrPDU([4]int{192, 168, 0, 1}, 2)}},
			}, nil
		}
		// A device that does not answer the system Get fails just this target.
		return &fakeSNMPSession{getErr: errors.New("request timeout")}, nil
	}

	obs, scanErrs, err := d.Discover(context.Background(), inventoryJob(
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

func TestClassifyOSFamily(t *testing.T) {
	tests := []struct{ in, want string }{
		{"", ""},
		{"Linux router 5.10.0", "Linux"},
		{"Hardware: Intel64, Software: Windows Version 6.3", "Windows"},
		{"Cisco IOS Software, C2960 Software", "Cisco IOS"},
		{"Juniper Networks, Inc. ex2200", "JunOS"},
		{"RouterOS RB750Gr3", "RouterOS"},
		{"Darwin Kernel Version 22.0.0", "macOS"},
		{"FreeBSD 13.1-RELEASE", "BSD"},
		{"Some Unknown Printer Firmware", ""},
	}
	for _, tt := range tests {
		if got := classifyOSFamily(tt.in); got != tt.want {
			t.Errorf("classifyOSFamily(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestIfIndexFromOIDSuffix(t *testing.T) {
	tests := []struct {
		oid  string
		want int
		ok   bool
	}{
		{oidIfPhysAddress + ".2", 2, true},
		{"." + oidIfDescr + ".15", 15, true},
		{oidIfPhysAddress + ".x", 0, false},
		{"", 0, false},
	}
	for _, tt := range tests {
		got, ok := ifIndexFromOIDSuffix(tt.oid)
		if ok != tt.ok || got != tt.want {
			t.Errorf("ifIndexFromOIDSuffix(%q) = %d,%v; want %d,%v", tt.oid, got, ok, tt.want, tt.ok)
		}
	}
}

func TestFormatUptime(t *testing.T) {
	tests := []struct {
		ticks uint32
		want  string
	}{
		{8640000, "1d 0h 0m"}, // 24h
		{360000, "1h 0m"},     // 1h
		{30000, "5m"},         // 5m
		{0, ""},
	}
	for _, tt := range tests {
		if got := formatUptime(gosnmp.SnmpPDU{Value: tt.ticks}); got != tt.want {
			t.Errorf("formatUptime(%d) = %q, want %q", tt.ticks, got, tt.want)
		}
	}
}

func TestInventoryValueExtractors(t *testing.T) {
	if got := octetString(gosnmp.SnmpPDU{Value: []byte("abc")}); got != "abc" {
		t.Errorf("octetString([]byte) = %q", got)
	}
	if got := octetString(gosnmp.SnmpPDU{Value: nil}); got != "" {
		t.Errorf("octetString(nil) = %q, want empty (NoSuchObject)", got)
	}
	if got := oidValue(gosnmp.SnmpPDU{Value: ".1.3.6.1.4.1.9"}); got != "1.3.6.1.4.1.9" {
		t.Errorf("oidValue = %q", got)
	}
	if n, ok := intFromPDU(gosnmp.SnmpPDU{Value: 7}); !ok || n != 7 {
		t.Errorf("intFromPDU(int) = %d,%v", n, ok)
	}
	if _, ok := intFromPDU(gosnmp.SnmpPDU{Value: "nope"}); ok {
		t.Errorf("intFromPDU(string) should not parse")
	}
}

// entClassPDU and entSerialPDU build ENTITY-MIB rows for the hardware-serial
// walks (ADR 0030).
func entClassPDU(idx, class int) gosnmp.SnmpPDU {
	return gosnmp.SnmpPDU{Name: oidEntPhysicalClass + "." + itoa(idx), Type: gosnmp.Integer, Value: class}
}

func entSerialPDU(idx int, serial string) gosnmp.SnmpPDU {
	return gosnmp.SnmpPDU{Name: oidEntPhysicalSerialNum + "." + itoa(idx), Type: gosnmp.OctetString, Value: []byte(serial)}
}

func TestSNMPInventoryReadsHardwareSerial(t *testing.T) {
	session := &fakeSNMPSession{
		getPDUs: []gosnmp.SnmpPDU{
			octet(oidSysName, "fw1"),
			octet(oidSysDescr, "FreeBSD OPNsense"),
			{Name: oidSysObjectID, Type: gosnmp.ObjectIdentifier, Value: ".1.3.6.1.4.1.12325.1.1.2.1.1"},
		},
		walks: map[string][]gosnmp.SnmpPDU{
			oidIPAdEntIfIndex: {ipAddrPDU([4]int{192, 168, 0, 1}, 2)},
			// A port module (class 10) with its own serial sits at a lower index
			// than the chassis (class 3): the chassis serial must still win.
			oidEntPhysicalClass:     {entClassPDU(1, 10), entClassPDU(2, entPhysicalClassChassis)},
			oidEntPhysicalSerialNum: {entSerialPDU(1, "PORT-42"), entSerialPDU(2, "CHASSIS-7")},
		},
	}
	d := NewSNMPDiscoverer(SNMPConfig{})
	d.dial = func(target string, cfg SNMPConfig) (snmpSession, error) { return session, nil }

	obs, scanErrs, err := d.Discover(context.Background(), inventoryJob(
		[]string{"192.168.0.1"}, []string{"192.168.0.0/24"}))
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if len(scanErrs) != 0 {
		t.Fatalf("unexpected scan errors: %+v", scanErrs)
	}
	if len(obs) != 1 {
		t.Fatalf("got %d observations, want 1: %+v", len(obs), obs)
	}
	o := obs[0]
	if o.HWSerial != "CHASSIS-7" {
		t.Errorf("HWSerial = %q, want CHASSIS-7 (chassis row must beat the module row)", o.HWSerial)
	}
	if o.HWObjectID != "1.3.6.1.4.1.12325.1.1.2.1.1" {
		t.Errorf("HWObjectID = %q", o.HWObjectID)
	}
	if !hasEvidence(o.Evidence, "Hardware serial: CHASSIS-7") {
		t.Errorf("missing serial evidence: %+v", o.Evidence)
	}
}

func TestChassisSerial(t *testing.T) {
	cases := []struct {
		name    string
		classes map[int]int
		serials map[int]string
		want    string
	}{
		{"empty", nil, nil, ""},
		{
			"chassis wins over lower-indexed module",
			map[int]int{1: 10, 5: entPhysicalClassChassis},
			map[int]string{1: "MOD-1", 5: "CHS-5"},
			"CHS-5",
		},
		{
			"fallback to first usable serial when no chassis row",
			map[int]int{3: 10, 4: 9},
			map[int]string{3: "MOD-3", 4: "FAN-4"},
			"MOD-3",
		},
		{
			"placeholder serials rejected",
			map[int]int{1: entPhysicalClassChassis, 2: 10},
			map[int]string{1: "N/A", 2: "REAL-2"},
			"REAL-2",
		},
		{
			"all placeholders yield nothing",
			map[int]int{1: entPhysicalClassChassis},
			map[int]string{1: "To be filled by O.E.M."},
			"",
		},
		{
			"chassis with empty serial falls back",
			map[int]int{1: entPhysicalClassChassis, 2: 10},
			map[int]string{1: "", 2: "MOD-2"},
			"MOD-2",
		},
	}
	for _, tc := range cases {
		if got := chassisSerial(tc.classes, tc.serials); got != tc.want {
			t.Errorf("%s: chassisSerial() = %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestUsableSerial(t *testing.T) {
	for serial, want := range map[string]bool{
		"CHS-5": true, "  ": false, "n/a": false, "NONE": false,
		"0": false, "Default string": false, "0012345": true,
	} {
		if got := usableSerial(serial); got != want {
			t.Errorf("usableSerial(%q) = %v, want %v", serial, got, want)
		}
	}
}
