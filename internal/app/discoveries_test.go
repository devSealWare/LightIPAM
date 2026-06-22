package app

import (
	"testing"

	"github.com/devSealWare/LightIPAM/internal/store"
)

func TestSuggestSubnetCIDR(t *testing.T) {
	tests := []struct {
		name    string
		ip      string
		targets []string
		want    string
		ok      bool
	}{
		// No scanned network known → the /24 heuristic fallback.
		{"fallback /24", "192.168.5.23", nil, "192.168.5.0/24", true},
		{"fallback for other ranges", "10.0.0.1", nil, "10.0.0.0/24", true},
		{"fallback at .255", "172.16.200.255", nil, "172.16.200.0/24", true},
		// A bare-IP or /32 target names the host, not a network: still falls back.
		{"bare-IP target ignored", "10.0.0.1", []string{"10.0.0.1"}, "10.0.0.0/24", true},
		{"/32 target ignored", "172.16.200.255", []string{"172.16.200.255/32"}, "172.16.200.0/24", true},
		// The scanned network wins — this is the bug fix. A /28 scan suggests /28.
		{"adopts scanned /28", "192.168.0.6", []string{"192.168.0.0/28"}, "192.168.0.0/28", true},
		{"adopts scanned /25", "10.1.2.130", []string{"10.1.2.128/25"}, "10.1.2.128/25", true},
		// A non-host-aligned target CIDR is masked to its network address.
		{"masks unaligned target", "192.168.0.6", []string{"192.168.0.6/28"}, "192.168.0.0/28", true},
		// The most specific containing target wins when several overlap.
		{"most specific wins", "192.168.0.6", []string{"192.168.0.0/24", "192.168.0.0/28"}, "192.168.0.0/28", true},
		// A target that does not contain the host is ignored (falls back to /24).
		{"non-containing target ignored", "192.168.9.5", []string{"192.168.0.0/28"}, "192.168.9.0/24", true},
		// Malformed targets never break the suggestion.
		{"malformed target skipped", "192.168.0.6", []string{"not-a-cidr", "192.168.0.0/29"}, "192.168.0.0/29", true},
		{"bad ip", "not-an-ip", nil, "", false},
		{"ipv6 rejected", "2001:db8::1", nil, "", false},
	}
	for _, tt := range tests {
		got, err := suggestSubnetCIDR(tt.ip, tt.targets)
		if tt.ok && err != nil {
			t.Errorf("%s: suggestSubnetCIDR(%q) unexpected error: %v", tt.name, tt.ip, err)
			continue
		}
		if !tt.ok && err == nil {
			t.Errorf("%s: suggestSubnetCIDR(%q) expected error, got %q", tt.name, tt.ip, got)
			continue
		}
		if got != tt.want {
			t.Errorf("%s: suggestSubnetCIDR(%q, %v) = %q, want %q", tt.name, tt.ip, tt.targets, got, tt.want)
		}
	}
}

func TestMissingSubnetGroups(t *testing.T) {
	targets := []store.DiscoveryImportTarget{
		{ID: "a", IP: "192.168.5.10", VLAN: 0, HasSubnet: false},
		{ID: "b", IP: "192.168.5.20", VLAN: 30, HasSubnet: false}, // same /24 as a, carries the VLAN
		{ID: "c", IP: "10.0.0.5", VLAN: 0, HasSubnet: false},      // a second missing /24
		{ID: "d", IP: "172.16.1.1", VLAN: 0, HasSubnet: true},     // already has a subnet — excluded
	}

	groups := missingSubnetGroups(targets)
	if len(groups) != 2 {
		t.Fatalf("expected 2 missing groups, got %d (%+v)", len(groups), groups)
	}

	// Sorted by ascending network: 10.0.0.0/24 before 192.168.5.0/24.
	if groups[0].CIDR != "10.0.0.0/24" {
		t.Errorf("first group CIDR = %q, want 10.0.0.0/24", groups[0].CIDR)
	}
	if groups[1].CIDR != "192.168.5.0/24" {
		t.Errorf("second group CIDR = %q, want 192.168.5.0/24", groups[1].CIDR)
	}

	// The 192.168.5.0/24 group folds in both hosts and adopts the first non-zero VLAN.
	five := groups[1]
	if five.Count != 2 {
		t.Errorf("192.168.5.0/24 count = %d, want 2", five.Count)
	}
	if five.VLAN != 30 {
		t.Errorf("192.168.5.0/24 VLAN = %d, want 30", five.VLAN)
	}
	if five.RepIP != "192.168.5.10" {
		t.Errorf("192.168.5.0/24 RepIP = %q, want 192.168.5.10", five.RepIP)
	}
}

func TestMissingSubnetGroupsAdoptsScannedCIDR(t *testing.T) {
	// Two hosts found by a /28 scan: they group under the scanned /28, not a /24.
	targets := []store.DiscoveryImportTarget{
		{ID: "a", IP: "192.168.0.6", ScannedTargets: []string{"192.168.0.0/28"}, VLAN: 12, HasSubnet: false},
		{ID: "b", IP: "192.168.0.9", ScannedTargets: []string{"192.168.0.0/28"}, HasSubnet: false},
	}
	groups := missingSubnetGroups(targets)
	if len(groups) != 1 {
		t.Fatalf("expected 1 group, got %d (%+v)", len(groups), groups)
	}
	g := groups[0]
	if g.CIDR != "192.168.0.0/28" {
		t.Errorf("group CIDR = %q, want 192.168.0.0/28 (the scanned network, not a /24)", g.CIDR)
	}
	if g.Count != 2 {
		t.Errorf("group count = %d, want 2", g.Count)
	}
	if g.RepIP != "192.168.0.6" {
		t.Errorf("group RepIP = %q, want 192.168.0.6", g.RepIP)
	}
	if g.VLAN != 12 {
		t.Errorf("group VLAN = %d, want 12", g.VLAN)
	}
}

func TestMissingSubnetGroupsAllResolved(t *testing.T) {
	targets := []store.DiscoveryImportTarget{
		{ID: "a", IP: "192.168.5.10", HasSubnet: true},
		{ID: "b", IP: "10.0.0.5", HasSubnet: true},
	}
	if groups := missingSubnetGroups(targets); len(groups) != 0 {
		t.Errorf("expected no missing groups, got %d", len(groups))
	}
}

func TestSubnetPromptCopy(t *testing.T) {
	one := subnetPrompt("import-one", "disc1", "192.168.5.23", 0, subnetPromptForm("192.168.5.0/24", 30))
	if one.Form["vlan"] != "30" {
		t.Errorf("import-one VLAN prefill = %q, want 30", one.Form["vlan"])
	}
	if one.Form["cidr"] != "192.168.5.0/24" {
		t.Errorf("import-one CIDR prefill = %q", one.Form["cidr"])
	}
	if one.Heading == "" || one.Context == "" {
		t.Error("import-one prompt missing heading/context copy")
	}

	// No VLAN learned → the field is left unset rather than "0".
	form := subnetPromptForm("10.0.0.0/24", 0)
	if _, set := form["vlan"]; set {
		t.Error("expected no VLAN key when the scan learned none")
	}

	all := subnetPrompt("import-all", "", "10.0.0.5", 3, form)
	if all.Remaining != 3 {
		t.Errorf("import-all Remaining = %d, want 3", all.Remaining)
	}
}
