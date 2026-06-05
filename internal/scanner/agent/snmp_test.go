package agent

import (
	"context"
	"errors"
	"testing"

	"github.com/devSealWare/LightIPAM/internal/scanner"
	"github.com/gosnmp/gosnmp"
)

// fakeSNMPSession returns canned PDUs (or an error) instead of touching a device.
type fakeSNMPSession struct {
	pdus     []gosnmp.SnmpPDU
	walkErr  error
	connErr  error
	closed   bool
	walkRoot string
}

func (f *fakeSNMPSession) Connect() error { return f.connErr }

func (f *fakeSNMPSession) BulkWalkAll(rootOID string) ([]gosnmp.SnmpPDU, error) {
	f.walkRoot = rootOID
	if f.walkErr != nil {
		return nil, f.walkErr
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
