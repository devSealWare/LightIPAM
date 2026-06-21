package app

import (
	"reflect"
	"testing"
)

func TestTranslateNetBoxSubnets(t *testing.T) {
	header := []string{"prefix", "status", "vlan_vid", "site", "description", "tenant"}
	records := [][]string{
		{"10.0.0.0/24", "active", "100", "HQ", "Server VLAN", "acme"},
		{"10.0.1.0/24", "container", "", "", "", ""},
	}
	ch, cr, ferr := translateNetBoxImport("subnets", header, records)
	if ferr != "" {
		t.Fatalf("unexpected file error: %s", ferr)
	}
	if !reflect.DeepEqual(ch, subnetCSVColumns) {
		t.Fatalf("canonical header = %v", ch)
	}
	// name <- description; vlan <- vlan_vid; description carried; site carried.
	if !reflect.DeepEqual(cr[0], []string{"Server VLAN", "10.0.0.0/24", "100", "HQ", "Server VLAN"}) {
		t.Fatalf("row0 = %v", cr[0])
	}
	// No description: name falls back to the prefix.
	if !reflect.DeepEqual(cr[1], []string{"10.0.1.0/24", "10.0.1.0/24", "", "", ""}) {
		t.Fatalf("row1 = %v", cr[1])
	}
}

func TestTranslateNetBoxSubnetsMissingPrefix(t *testing.T) {
	_, _, ferr := translateNetBoxImport("subnets", []string{"status", "site"}, [][]string{{"active", "HQ"}})
	if ferr == "" {
		t.Fatal("expected a missing-prefix-column error")
	}
}

func TestTranslateNetBoxAddresses(t *testing.T) {
	header := []string{"address", "status", "dns_name", "description"}
	records := [][]string{
		{"10.0.0.5/24", "active", "host.example.com", "primary"},
		{"10.0.0.6/24", "reserved", "", ""},
		{"10.0.0.7", "deprecated", "old.example.com", "retire"},
		{"10.0.0.8/24", "dhcp", "", ""},
	}
	ch, cr, ferr := translateNetBoxImport("addresses", header, records)
	if ferr != "" {
		t.Fatalf("unexpected file error: %s", ferr)
	}
	if !reflect.DeepEqual(ch, addressCSVColumns) {
		t.Fatalf("canonical header = %v", ch)
	}
	// address mask stripped; status mapped; dns_name -> hostname; description -> notes.
	if !reflect.DeepEqual(cr[0], []string{"10.0.0.5", "", "assigned", "host.example.com", "", "primary"}) {
		t.Fatalf("row0 = %v", cr[0])
	}
	if cr[1][2] != "reserved" {
		t.Fatalf("reserved status mapping = %v", cr[1])
	}
	if cr[2][2] != "deprecated" || cr[2][0] != "10.0.0.7" {
		t.Fatalf("deprecated row = %v", cr[2])
	}
	if cr[3][2] != "assigned" {
		t.Fatalf("dhcp should map to assigned, got %v", cr[3])
	}
}

func TestTranslateNetBoxDevices(t *testing.T) {
	header := []string{"name", "device_role", "comments", "site"}
	records := [][]string{
		{"sw-core-1", "switch", "core switch", "HQ"},
		{"", "router", "", ""},
	}
	ch, cr, ferr := translateNetBoxImport("devices", header, records)
	if ferr != "" {
		t.Fatalf("unexpected file error: %s", ferr)
	}
	if !reflect.DeepEqual(ch, deviceCSVColumns) {
		t.Fatalf("canonical header = %v", ch)
	}
	// description falls back to comments when there is no description column.
	if !reflect.DeepEqual(cr[0], []string{"sw-core-1", "core switch"}) {
		t.Fatalf("row0 = %v", cr[0])
	}
	// An empty name is left for the existing validator to reject (not dropped).
	if cr[1][0] != "" {
		t.Fatalf("row1 name = %q", cr[1][0])
	}
	if len(cr) != 2 {
		t.Fatalf("row count changed: %d", len(cr))
	}
}

func TestNetBoxStatusMaps(t *testing.T) {
	for in, want := range map[string]string{
		"active": "assigned", "dhcp": "assigned", "slaac": "assigned", "": "assigned",
		"reserved": "reserved", "deprecated": "deprecated", "weird": "assigned", "ACTIVE": "assigned",
	} {
		if got := mapNetBoxIPStatus(in); got != want {
			t.Errorf("mapNetBoxIPStatus(%q) = %q, want %q", in, got, want)
		}
	}
	for in, want := range map[string]string{
		"assigned": "active", "available": "active", "conflict": "active",
		"reserved": "reserved", "deprecated": "deprecated",
	} {
		if got := reverseNetBoxIPStatus(in); got != want {
			t.Errorf("reverseNetBoxIPStatus(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNetBoxHelpers(t *testing.T) {
	if stripMask("10.0.0.5/24") != "10.0.0.5" || stripMask("10.0.0.6") != "10.0.0.6" {
		t.Error("stripMask failed")
	}
	if netboxAddressString("10.0.0.5", "10.0.0.0/24") != "10.0.0.5/24" {
		t.Error("netboxAddressString with subnet failed")
	}
	if netboxAddressString("10.0.0.5", "") != "10.0.0.5/32" {
		t.Error("netboxAddressString fallback failed")
	}
	if firstNonEmpty("", "  ", "x", "y") != "x" {
		t.Error("firstNonEmpty failed")
	}
	if normalizeImportFormat("NetBox") != formatNetBox || normalizeImportFormat("") != formatLightIPAM {
		t.Error("normalizeImportFormat failed")
	}
}
