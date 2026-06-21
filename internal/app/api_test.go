package app

import "testing"

func TestSubnetReqToInput(t *testing.T) {
	vlan := 100
	in, msg := subnetReq{CIDR: "10.0.0.0/24", Name: "Core", VLAN: &vlan}.toInput()
	if msg != "" {
		t.Fatalf("unexpected error: %s", msg)
	}
	if in.CIDR != "10.0.0.0/24" || in.Name != "Core" || in.VLAN == nil || *in.VLAN != 100 {
		t.Fatalf("unexpected input: %+v", in)
	}
	if in.SiteID != "default" {
		t.Fatalf("expected default site, got %q", in.SiteID)
	}

	if _, msg := (subnetReq{CIDR: "10.0.0.0/24", SiteID: "hq", Name: "x"}).toInput(); msg != "" {
		t.Fatalf("site override should be accepted: %s", msg)
	}

	bad := []subnetReq{
		{CIDR: "10.0.0.0/24"},                             // missing name
		{CIDR: "not-a-cidr", Name: "x"},                   // bad cidr
		{CIDR: "10.0.0.0/24", Name: "x", VLAN: ptr(0)},    // vlan too low
		{CIDR: "10.0.0.0/24", Name: "x", VLAN: ptr(5000)}, // vlan too high
	}
	for i, b := range bad {
		if _, msg := b.toInput(); msg == "" {
			t.Errorf("case %d: expected validation error", i)
		}
	}
}

func TestAddressReqToInput(t *testing.T) {
	in, msg := addressReq{Address: "10.0.0.5", State: "reserved", Hostname: "h"}.toInput()
	if msg != "" {
		t.Fatalf("unexpected error: %s", msg)
	}
	if in.Address != "10.0.0.5" || in.State != "reserved" || in.Hostname != "h" {
		t.Fatalf("unexpected input: %+v", in)
	}

	// Empty state defaults to assigned.
	in, msg = addressReq{Address: "10.0.0.6"}.toInput()
	if msg != "" || in.State != "assigned" {
		t.Fatalf("expected default assigned state, got %q (%s)", in.State, msg)
	}

	if _, msg := (addressReq{Address: "nope"}).toInput(); msg == "" {
		t.Error("expected a bad-address error")
	}
	if _, msg := (addressReq{Address: "10.0.0.7", State: "bogus"}).toInput(); msg == "" {
		t.Error("expected an invalid-state error")
	}
}

func ptr(v int) *int { return &v }
