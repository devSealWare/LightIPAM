package app

import (
	"testing"

	"github.com/devSealWare/LightIPAM/internal/store"
)

func TestSuggestSubnetCIDR(t *testing.T) {
	tests := []struct {
		ip   string
		want string
		ok   bool
	}{
		{"192.168.5.23", "192.168.5.0/24", true},
		{"10.0.0.1", "10.0.0.0/24", true},
		{"172.16.200.255", "172.16.200.0/24", true},
		{"not-an-ip", "", false},
		{"2001:db8::1", "", false}, // IPv4 only
	}
	for _, tt := range tests {
		got, err := suggestSubnetCIDR(tt.ip)
		if tt.ok && err != nil {
			t.Errorf("suggestSubnetCIDR(%q) unexpected error: %v", tt.ip, err)
			continue
		}
		if !tt.ok && err == nil {
			t.Errorf("suggestSubnetCIDR(%q) expected error, got %q", tt.ip, got)
			continue
		}
		if got != tt.want {
			t.Errorf("suggestSubnetCIDR(%q) = %q, want %q", tt.ip, got, tt.want)
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
