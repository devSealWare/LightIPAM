package agent

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/devSealWare/LightIPAM/internal/scanner"
)

// --- packet builders for hermetic tests (no sockets) ---

type nbName struct {
	name   string
	suffix byte
	group  bool
}

func padNetBIOSName(s string) []byte {
	out := make([]byte, 15)
	for i := range out {
		out[i] = ' '
	}
	copy(out, s)
	return out
}

// buildNBStatResponse assembles a NetBIOS node-status response with the given
// name entries, matching the layout parseNBStatResponse expects.
func buildNBStatResponse(names []nbName) []byte {
	var b []byte
	// Header: id, flags (response), QDCOUNT 0, ANCOUNT 1, NSCOUNT/ARCOUNT 0.
	b = append(b, 0x4c, 0x49, 0x84, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00)
	// Echoed RR name (the encoded wildcard "*").
	enc := encodeNetBIOSName("*")
	b = append(b, byte(len(enc)))
	b = append(b, enc...)
	b = append(b, 0x00)
	// RR fixed fields: TYPE(2) CLASS(2) TTL(4) RDLENGTH(2) — value unused by parser.
	b = append(b, 0x00, 0x21, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
	// Node-status payload: name count then 18-byte entries.
	b = append(b, byte(len(names)))
	for _, n := range names {
		var entry [18]byte
		copy(entry[:15], padNetBIOSName(n.name))
		entry[15] = n.suffix
		var flags uint16
		if n.group {
			flags |= 0x8000
		}
		binary.BigEndian.PutUint16(entry[16:18], flags)
		b = append(b, entry[:]...)
	}
	// A short statistics block follows in a real response; the parser stops after
	// the entries, so its contents do not matter.
	b = append(b, make([]byte, 8)...)
	return b
}

// buildMDNSPTRResponse assembles an mDNS reverse-lookup response whose single PTR
// answer points at ptrName, with the answer NAME as a compression pointer back to
// the question (exercising the pointer-aware skip/read).
func buildMDNSPTRResponse(ip, ptrName string) []byte {
	var b []byte
	// Header: id 0, flags response, QDCOUNT 1, ANCOUNT 1.
	b = append(b, 0x00, 0x00, 0x84, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00)
	qstart := len(b) // 12
	addr := netip.MustParseAddr(ip).As4()
	qname := fmt.Sprintf("%d.%d.%d.%d.in-addr.arpa", addr[3], addr[2], addr[1], addr[0])
	b = appendDNSName(b, qname)
	b = append(b, 0x00, 0x0c, 0x80, 0x01) // QTYPE PTR, QCLASS IN+QU
	// Answer: NAME = pointer to the question, TYPE PTR, CLASS, TTL, RDLENGTH, RDATA.
	b = append(b, 0xc0, byte(qstart))
	b = append(b, 0x00, 0x0c)             // TYPE PTR
	b = append(b, 0x80, 0x01)             // CLASS IN + cache-flush
	b = append(b, 0x00, 0x00, 0x00, 0x78) // TTL 120
	var rdata []byte
	rdata = appendDNSName(rdata, ptrName)
	b = append(b, byte(len(rdata)>>8), byte(len(rdata)))
	b = append(b, rdata...)
	return b
}

// --- encoding/parsing unit tests ---

func TestEncodeNetBIOSWildcard(t *testing.T) {
	got := string(encodeNetBIOSName("*"))
	// '*' (0x2A) → "CK"; each of the 15 trailing NUL bytes → "AA".
	want := "CK" + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	if len(got) != 32 {
		t.Fatalf("encoded name must be 32 bytes, got %d (%q)", len(got), got)
	}
	if got != want {
		t.Fatalf("encodeNetBIOSName(*) = %q, want %q", got, want)
	}
}

func TestNBStatRequestFormat(t *testing.T) {
	req := nbstatRequest()
	// 12-byte header + 1 length byte + 32 name bytes + 1 terminator + 4 (type+class).
	if len(req) != 50 {
		t.Fatalf("nbstat request length = %d, want 50", len(req))
	}
	if req[11] != 0x00 || binary.BigEndian.Uint16(req[4:6]) != 1 {
		t.Fatalf("expected QDCOUNT 1 in header, got % x", req[:12])
	}
	if req[12] != 0x20 {
		t.Fatalf("expected 0x20 label length, got 0x%02x", req[12])
	}
	if qtype := binary.BigEndian.Uint16(req[len(req)-4 : len(req)-2]); qtype != 0x0021 {
		t.Fatalf("expected QTYPE NBSTAT (0x21), got 0x%04x", qtype)
	}
	if qclass := binary.BigEndian.Uint16(req[len(req)-2:]); qclass != 0x0001 {
		t.Fatalf("expected QCLASS IN, got 0x%04x", qclass)
	}
}

func TestParseNBStatResponse(t *testing.T) {
	resp := buildNBStatResponse([]nbName{
		{name: "MYPC", suffix: 0x00, group: false},     // machine name
		{name: "WORKGROUP", suffix: 0x00, group: true}, // workgroup
		{name: "MYPC", suffix: 0x20, group: false},     // file server service (ignored)
		{name: "ADMIN", suffix: 0x03, group: false},    // messenger (ignored)
	})
	name, group, err := parseNBStatResponse(resp)
	if err != nil {
		t.Fatalf("parseNBStatResponse: %v", err)
	}
	if name != "MYPC" {
		t.Fatalf("machine name = %q, want MYPC", name)
	}
	if group != "WORKGROUP" {
		t.Fatalf("workgroup = %q, want WORKGROUP", group)
	}
}

func TestParseNBStatResponseNoNames(t *testing.T) {
	// Only non-0x00-suffix names: nothing identifies the host.
	resp := buildNBStatResponse([]nbName{{name: "SVC", suffix: 0x20, group: false}})
	if _, _, err := parseNBStatResponse(resp); err == nil {
		t.Fatal("expected an error when no suffix-0x00 names are present")
	}
}

func TestParseNBStatResponseTooShort(t *testing.T) {
	if _, _, err := parseNBStatResponse([]byte{0x00, 0x01, 0x02}); err == nil {
		t.Fatal("expected an error for a truncated response")
	}
}

func TestMDNSReverseRequest(t *testing.T) {
	req, err := mdnsReverseRequest("192.168.1.5")
	if err != nil {
		t.Fatalf("mdnsReverseRequest: %v", err)
	}
	if binary.BigEndian.Uint16(req[4:6]) != 1 {
		t.Fatalf("expected QDCOUNT 1, got % x", req[:12])
	}
	name, next, err := readDNSName(req, 12)
	if err != nil {
		t.Fatalf("readDNSName: %v", err)
	}
	if name != "5.1.168.192.in-addr.arpa" {
		t.Fatalf("reverse qname = %q, want 5.1.168.192.in-addr.arpa", name)
	}
	if qtype := binary.BigEndian.Uint16(req[next : next+2]); qtype != 0x000c {
		t.Fatalf("expected QTYPE PTR, got 0x%04x", qtype)
	}
	if qclass := binary.BigEndian.Uint16(req[next+2 : next+4]); qclass != 0x8001 {
		t.Fatalf("expected QCLASS with QU bit (0x8001), got 0x%04x", qclass)
	}
}

func TestMDNSReverseRequestRejectsNonIPv4(t *testing.T) {
	if _, err := mdnsReverseRequest("not-an-ip"); err == nil {
		t.Fatal("expected an error for a non-IPv4 target")
	}
}

func TestParseMDNSPTRResponse(t *testing.T) {
	resp := buildMDNSPTRResponse("192.168.1.5", "Brennans-MacBook.local")
	name, err := parseMDNSPTRResponse(resp)
	if err != nil {
		t.Fatalf("parseMDNSPTRResponse: %v", err)
	}
	if name != "Brennans-MacBook.local" {
		t.Fatalf("ptr name = %q, want Brennans-MacBook.local", name)
	}
}

func TestParseMDNSPTRResponseNoAnswers(t *testing.T) {
	// Header claiming zero answers.
	resp := []byte{0x00, 0x00, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	if _, err := parseMDNSPTRResponse(resp); err == nil {
		t.Fatal("expected an error when the response has no answers")
	}
}

func TestReadDNSNameCompression(t *testing.T) {
	// "local" at offset 0, then "host" + pointer back to it at offset 7.
	buf := []byte{0x05, 'l', 'o', 'c', 'a', 'l', 0x00,
		0x04, 'h', 'o', 's', 't', 0xc0, 0x00}
	name, next, err := readDNSName(buf, 7)
	if err != nil {
		t.Fatalf("readDNSName: %v", err)
	}
	if name != "host.local" {
		t.Fatalf("name = %q, want host.local", name)
	}
	if next != 14 {
		t.Fatalf("next = %d, want 14 (just past the pointer)", next)
	}
}

func TestReadDNSNameLoops(t *testing.T) {
	// A pointer at offset 0 that points to itself: must not spin forever.
	buf := []byte{0xc0, 0x00}
	if _, _, err := readDNSName(buf, 0); err == nil {
		t.Fatal("expected a compression-loop error")
	}
}

// --- discoverer dispatch tests (fake UDP exchange) ---

func nameJob(targets ...string) scanner.ScanJob {
	return scanner.ScanJob{
		ID:           "job-names",
		AgentID:      "agent-1",
		Type:         scanner.ScanNameLookup,
		Mode:         scanner.ModeStandardActive,
		AllowedCIDRs: []string{"192.168.1.0/24"},
		Targets:      targets,
	}
}

func TestNameDiscoverMergesBothProtocols(t *testing.T) {
	d := NewNameDiscoverer(NameConfig{})
	d.exchange = func(_ context.Context, addr string, _ []byte, _ time.Duration) ([]byte, error) {
		_, port, _ := net.SplitHostPort(addr)
		switch port {
		case "137":
			return buildNBStatResponse([]nbName{
				{name: "MYPC", suffix: 0x00, group: false},
				{name: "WORKGROUP", suffix: 0x00, group: true},
			}), nil
		case "5353":
			return buildMDNSPTRResponse("192.168.1.5", "mypc.local"), nil
		default:
			return nil, fmt.Errorf("unexpected port %q", port)
		}
	}

	obs, errs, err := d.Discover(context.Background(), nameJob("192.168.1.5"))
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if len(errs) != 0 {
		t.Fatalf("expected no errors, got %+v", errs)
	}
	if len(obs) != 1 {
		t.Fatalf("expected one observation, got %d: %+v", len(obs), obs)
	}
	got := obs[0]
	if got.IP != "192.168.1.5" {
		t.Fatalf("ip = %q", got.IP)
	}
	// NetBIOS leads for the hostname; mDNS rides as evidence.
	if got.Hostname != "MYPC" {
		t.Fatalf("hostname = %q, want MYPC (NetBIOS leads)", got.Hostname)
	}
	if len(got.Evidence) != 2 {
		t.Fatalf("expected NetBIOS + mDNS evidence, got %+v", got.Evidence)
	}
}

func TestNameDiscoverMDNSOnly(t *testing.T) {
	d := NewNameDiscoverer(NameConfig{})
	d.exchange = func(_ context.Context, addr string, _ []byte, _ time.Duration) ([]byte, error) {
		_, port, _ := net.SplitHostPort(addr)
		if port == "5353" {
			return buildMDNSPTRResponse("192.168.1.5", "appletv.local"), nil
		}
		return nil, fmt.Errorf("netbios silent")
	}

	obs, _, err := d.Discover(context.Background(), nameJob("192.168.1.5"))
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if len(obs) != 1 {
		t.Fatalf("expected one observation, got %+v", obs)
	}
	// With no NetBIOS name, mDNS fills the hostname (the ".local" suffix trimmed).
	if obs[0].Hostname != "appletv" {
		t.Fatalf("hostname = %q, want appletv", obs[0].Hostname)
	}
}

func TestNameDiscoverSilentHostIsUnresolved(t *testing.T) {
	d := NewNameDiscoverer(NameConfig{})
	d.exchange = func(_ context.Context, _ string, _ []byte, _ time.Duration) ([]byte, error) {
		return nil, fmt.Errorf("no response")
	}

	obs, errs, err := d.Discover(context.Background(), nameJob("192.168.1.5"))
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if len(obs) != 0 {
		t.Fatalf("expected no observation for a silent host, got %+v", obs)
	}
	if len(errs) != 1 || errs[0].Code != "name_unresolved" {
		t.Fatalf("expected one name_unresolved error, got %+v", errs)
	}
}

func TestNameDiscoverRejectsCIDRTarget(t *testing.T) {
	d := NewNameDiscoverer(NameConfig{})
	d.exchange = func(_ context.Context, _ string, _ []byte, _ time.Duration) ([]byte, error) {
		t.Fatal("a CIDR target must not be probed")
		return nil, nil
	}

	obs, errs, err := d.Discover(context.Background(), nameJob("192.168.1.0/24"))
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if len(obs) != 0 {
		t.Fatalf("expected no observation for a CIDR target, got %+v", obs)
	}
	if len(errs) != 1 || errs[0].Code != "name_unresolved" {
		t.Fatalf("expected a name_unresolved notice for the CIDR, got %+v", errs)
	}
}

func TestNameDiscoverPassiveShortCircuits(t *testing.T) {
	d := NewNameDiscoverer(NameConfig{})
	d.exchange = func(_ context.Context, _ string, _ []byte, _ time.Duration) ([]byte, error) {
		t.Fatal("passive mode must send no packets")
		return nil, nil
	}

	job := nameJob("192.168.1.5")
	job.Mode = scanner.ModePassive
	obs, errs, err := d.Discover(context.Background(), job)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if len(obs) != 0 || len(errs) != 0 {
		t.Fatalf("passive scan should yield nothing, got obs=%+v errs=%+v", obs, errs)
	}
}
