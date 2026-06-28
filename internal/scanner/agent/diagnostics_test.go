package agent

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/devSealWare/LightIPAM/internal/scanner"
)

func TestParseNmapVersion(t *testing.T) {
	cases := map[string]string{
		"Nmap version 7.94 ( https://nmap.org )":    "7.94",
		"Nmap version 7.80SVN ( https://nmap.org )": "7.80SVN",
		"":                "",
		"nmap: not found": "",
	}
	for in, want := range cases {
		if got := parseNmapVersion(in); got != want {
			t.Errorf("parseNmapVersion(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseDefaultRouteInterface(t *testing.T) {
	// A trimmed /proc/net/route: eth0 has the gateway/default (Destination 00000000),
	// the other rows are directly-connected subnets.
	route := "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\n" +
		"eth1\t0000110A\t00000000\t0001\t0\t0\t0\t0000FFFF\n" +
		"eth0\t00000000\t0100A8C0\t0003\t0\t0\t0\t00000000\n"
	if got := parseDefaultRouteInterface(route); got != "eth0" {
		t.Fatalf("parseDefaultRouteInterface = %q, want eth0", got)
	}
	// No default route present.
	noDefault := "Iface\tDestination\tGateway\neth1\t0000110A\t00000000\n"
	if got := parseDefaultRouteInterface(noDefault); got != "" {
		t.Fatalf("expected no default route, got %q", got)
	}
}

func TestParseEffectiveCaps(t *testing.T) {
	// CapEff 0x2000 = bit 13 = CAP_NET_RAW (the hardened agent's only capability).
	status := "Name:\tscanner-agent\nCapEff:\t0000000000002000\nSeccomp:\t2\n"
	caps := parseEffectiveCaps(status)
	if len(caps) != 1 || caps[0] != "NET_RAW" {
		t.Fatalf("parseEffectiveCaps = %v, want [NET_RAW]", caps)
	}
	// A couple of bits set: CHOWN (0) + NET_ADMIN (12) + NET_RAW (13) = 0x3001.
	caps = parseEffectiveCaps("CapEff:\t0000000000003001\n")
	want := []string{"CHOWN", "NET_ADMIN", "NET_RAW"}
	if strings.Join(caps, ",") != strings.Join(want, ",") {
		t.Fatalf("parseEffectiveCaps = %v, want %v", caps, want)
	}
	// No CapEff line.
	if got := parseEffectiveCaps("Name:\tx\n"); got != nil {
		t.Fatalf("expected nil caps when CapEff is absent, got %v", got)
	}
}

func TestDiagnosticsWarnings(t *testing.T) {
	srcNet := mustNet(t, "192.168.0.0/28")

	// No pin configured: no warnings.
	if w := diagnosticsWarnings(EgressOptions{}, "eth0"); len(w) != 0 {
		t.Fatalf("no pin should yield no warnings, got %v", w)
	}

	// auto, source interface differs from the default route: a not-pinned note.
	autoEgress := EgressOptions{Interface: "eth0", SourceIP: "192.168.0.9", PinMode: PinAuto, SourceNet: srcNet}
	w := diagnosticsWarnings(autoEgress, "eth1")
	if len(w) != 1 || !strings.Contains(w[0], "not pinned") {
		t.Fatalf("auto mismatch should warn about routed targets using the default route, got %v", w)
	}

	// always with the same mismatch: warn that routed probes are dropped.
	alwaysEgress := autoEgress
	alwaysEgress.PinMode = PinAlways
	w = diagnosticsWarnings(alwaysEgress, "eth1")
	if len(w) != 1 || !strings.Contains(w[0], "dropped") {
		t.Fatalf("always mismatch should warn that routed probes are dropped, got %v", w)
	}

	// Source on the same interface as the default route: no mismatch warning.
	if w := diagnosticsWarnings(autoEgress, "eth0"); len(w) != 0 {
		t.Fatalf("matching interface should not warn, got %v", w)
	}

	// Pin configured but the source subnet could not be resolved.
	w = diagnosticsWarnings(EgressOptions{SourceIP: "192.168.0.9", PinMode: PinAuto}, "")
	if len(w) != 1 || !strings.Contains(w[0], "could not") && !strings.Contains(w[0], "Could not") {
		t.Fatalf("unknown source subnet should warn, got %v", w)
	}
}

func TestCollectDiagnosticsUsesSeams(t *testing.T) {
	a := New(Config{
		Registration: testRegistration(),
		Egress: EgressOptions{
			Interface: "eth0",
			SourceIP:  "192.168.0.9",
			PinMode:   PinAuto,
			SourceNet: mustNet(t, "192.168.0.0/28"),
		},
	})
	// Override the system seams so the assembly is hermetic.
	a.sysInterfaces = func() []scanner.NetworkInterface {
		return []scanner.NetworkInterface{{Name: "eth0", Addrs: []string{"192.168.0.9/28"}}}
	}
	a.sysDefaultRoute = func() string { return "eth1" }
	a.sysCapabilities = func() []string { return []string{"NET_RAW"} }
	a.nmapVersion = func(context.Context) string { return "7.94" }

	d := a.collectDiagnostics(context.Background())
	if d.AgentID != "agent-1" {
		t.Errorf("agent id = %q", d.AgentID)
	}
	if d.ScanSourceIP != "192.168.0.9" || d.ResolvedScanInterface != "eth0" || d.DefaultRouteInterface != "eth1" {
		t.Errorf("source/route fields wrong: %+v", d)
	}
	if d.PinMode != "auto" || d.NmapVersion != "7.94" {
		t.Errorf("pin mode / nmap version wrong: %+v", d)
	}
	if len(d.Capabilities) != 1 || d.Capabilities[0] != "NET_RAW" {
		t.Errorf("capabilities = %v", d.Capabilities)
	}
	// eth0 (source) ≠ eth1 (default route) → a routing warning is computed.
	if len(d.Warnings) != 1 {
		t.Errorf("expected one mismatch warning, got %v", d.Warnings)
	}
}

func TestDiagnosticsEndpointOverMTLS(t *testing.T) {
	srv, client, _ := startMTLS(t)
	resp, err := client.Get(srv.URL + "/diagnostics")
	if err != nil {
		t.Fatalf("get diagnostics: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	var d scanner.AgentDiagnostics
	if err := json.NewDecoder(resp.Body).Decode(&d); err != nil {
		t.Fatalf("decode diagnostics: %v", err)
	}
	if d.AgentID != testRegistration().ID {
		t.Fatalf("diagnostics agent id = %q, want %q", d.AgentID, testRegistration().ID)
	}
	// Egress is the zero value here, so the pin mode normalizes to the default.
	if d.PinMode != string(PinAuto) {
		t.Fatalf("default pin mode = %q, want %q", d.PinMode, PinAuto)
	}
}
