package store

import "testing"

func TestSameHardwareCandidate(t *testing.T) {
	// The real-world sample this feature was built from: one OPNsense box
	// ("Archer_A7.internal") appearing as three gateway records, one per subnet,
	// each with a different port MAC — and nmap reading different FreeBSD
	// releases per interface. All three pairs must match on family alone.
	gw0 := deviceIdentity{Hostname: "Archer_A7.internal", OSFamily: "FreeBSD", SubnetIDs: []string{"net-0"}}
	gw1 := deviceIdentity{Hostname: "Archer_A7.internal", OSFamily: "FreeBSD", SubnetIDs: []string{"net-1"}}
	gw2 := deviceIdentity{Hostname: "Archer_A7.internal", OSFamily: "FreeBSD", SubnetIDs: []string{"net-2"}}

	cases := []struct {
		name string
		a, b deviceIdentity
		want bool
	}{
		{"archer gateways 0-1", gw0, gw1, true},
		{"archer gateways 0-2", gw0, gw2, true},
		{"archer gateways 1-2", gw1, gw2, true},
		{
			// os_detail is not part of the identity at all — same family with
			// different release strings still matches.
			"differing os_detail same family",
			deviceIdentity{Hostname: "fw.lan", OSFamily: "FreeBSD", SubnetIDs: []string{"a"}},
			deviceIdentity{Hostname: "fw.lan", OSFamily: "FreeBSD", SubnetIDs: []string{"b"}},
			true,
		},
		{
			"hostname trimmed and case-insensitive",
			deviceIdentity{Hostname: "  Archer_A7.INTERNAL ", OSFamily: "FreeBSD", SubnetIDs: []string{"a"}},
			deviceIdentity{Hostname: "archer_a7.internal", OSFamily: "freebsd", SubnetIDs: []string{"b"}},
			true,
		},
		{
			// Two hosts in one subnet are different machines: a true multi-homed
			// device has at most one IP per subnet.
			"shared subnet never matches",
			deviceIdentity{Hostname: "fw.lan", OSFamily: "FreeBSD", SubnetIDs: []string{"a", "b"}},
			deviceIdentity{Hostname: "fw.lan", OSFamily: "FreeBSD", SubnetIDs: []string{"b", "c"}},
			false,
		},
		{
			"same single subnet never matches",
			deviceIdentity{Hostname: "fw.lan", OSFamily: "FreeBSD", SubnetIDs: []string{"a"}},
			deviceIdentity{Hostname: "fw.lan", OSFamily: "FreeBSD", SubnetIDs: []string{"a"}},
			false,
		},
		{
			"empty hostname never matches",
			deviceIdentity{Hostname: "", OSFamily: "FreeBSD", SubnetIDs: []string{"a"}},
			deviceIdentity{Hostname: "", OSFamily: "FreeBSD", SubnetIDs: []string{"b"}},
			false,
		},
		{
			"different hostname",
			deviceIdentity{Hostname: "fw.lan", OSFamily: "FreeBSD", SubnetIDs: []string{"a"}},
			deviceIdentity{Hostname: "nas.lan", OSFamily: "FreeBSD", SubnetIDs: []string{"b"}},
			false,
		},
		{
			"empty os family never matches",
			deviceIdentity{Hostname: "fw.lan", OSFamily: "", SubnetIDs: []string{"a"}},
			deviceIdentity{Hostname: "fw.lan", OSFamily: "", SubnetIDs: []string{"b"}},
			false,
		},
		{
			"different os family",
			deviceIdentity{Hostname: "fw.lan", OSFamily: "FreeBSD", SubnetIDs: []string{"a"}},
			deviceIdentity{Hostname: "fw.lan", OSFamily: "Linux", SubnetIDs: []string{"b"}},
			false,
		},
		{
			"no subnets never matches",
			deviceIdentity{Hostname: "fw.lan", OSFamily: "FreeBSD", SubnetIDs: nil},
			deviceIdentity{Hostname: "fw.lan", OSFamily: "FreeBSD", SubnetIDs: []string{"b"}},
			false,
		},
	}
	for _, tc := range cases {
		if got := sameHardwareCandidate(tc.a, tc.b); got != tc.want {
			t.Errorf("%s: sameHardwareCandidate(%+v, %+v) = %v, want %v", tc.name, tc.a, tc.b, got, tc.want)
		}
		// The rule is symmetric by construction; hold it to that.
		if got := sameHardwareCandidate(tc.b, tc.a); got != tc.want {
			t.Errorf("%s (reversed): sameHardwareCandidate(%+v, %+v) = %v, want %v", tc.name, tc.b, tc.a, got, tc.want)
		}
	}
}

func TestGoldHardwareCandidate(t *testing.T) {
	cases := []struct {
		name string
		a, b deviceIdentity
		want bool
	}{
		{
			// The gold signal needs no hostname/OS agreement at all: the same
			// chassis serial across disjoint subnets is the physical unit.
			"serial match ignores hostname and os",
			deviceIdentity{Hostname: "gw0", OSFamily: "FreeBSD", HWSerial: "CHS-7", SubnetIDs: []string{"a"}},
			deviceIdentity{Hostname: "gw1", OSFamily: "", HWSerial: "CHS-7", SubnetIDs: []string{"b"}},
			true,
		},
		{
			"serial trimmed before compare",
			deviceIdentity{HWSerial: " CHS-7 ", SubnetIDs: []string{"a"}},
			deviceIdentity{HWSerial: "CHS-7", SubnetIDs: []string{"b"}},
			true,
		},
		{
			// Serials name one unit; case is preserved, not folded.
			"serial compare is case-sensitive",
			deviceIdentity{HWSerial: "chs-7", SubnetIDs: []string{"a"}},
			deviceIdentity{HWSerial: "CHS-7", SubnetIDs: []string{"b"}},
			false,
		},
		{
			"empty serials never match",
			deviceIdentity{HWSerial: "", SubnetIDs: []string{"a"}},
			deviceIdentity{HWSerial: "", SubnetIDs: []string{"b"}},
			false,
		},
		{
			// Cloned-serial guard: same subnet means two hosts, even at gold.
			"shared subnet blocks a serial match",
			deviceIdentity{HWSerial: "CHS-7", SubnetIDs: []string{"a"}},
			deviceIdentity{HWSerial: "CHS-7", SubnetIDs: []string{"a", "b"}},
			false,
		},
		{
			"no subnets blocks a serial match",
			deviceIdentity{HWSerial: "CHS-7", SubnetIDs: nil},
			deviceIdentity{HWSerial: "CHS-7", SubnetIDs: []string{"b"}},
			false,
		},
		{
			"different serials",
			deviceIdentity{HWSerial: "CHS-7", SubnetIDs: []string{"a"}},
			deviceIdentity{HWSerial: "CHS-8", SubnetIDs: []string{"b"}},
			false,
		},
	}
	for _, tc := range cases {
		if got := goldHardwareCandidate(tc.a, tc.b); got != tc.want {
			t.Errorf("%s: goldHardwareCandidate(%+v, %+v) = %v, want %v", tc.name, tc.a, tc.b, got, tc.want)
		}
		if got := goldHardwareCandidate(tc.b, tc.a); got != tc.want {
			t.Errorf("%s (reversed): goldHardwareCandidate(%+v, %+v) = %v, want %v", tc.name, tc.b, tc.a, got, tc.want)
		}
	}
}

func TestSingleHostname(t *testing.T) {
	cases := []struct {
		name string
		in   []string
		want string
	}{
		{"none", nil, ""},
		{"one", []string{"archer_a7.internal"}, "archer_a7.internal"},
		{"ambiguous", []string{"archer_a7.internal", "other.internal"}, ""},
	}
	for _, tc := range cases {
		if got := singleHostname(tc.in); got != tc.want {
			t.Errorf("%s: singleHostname(%v) = %q, want %q", tc.name, tc.in, got, tc.want)
		}
	}
}
