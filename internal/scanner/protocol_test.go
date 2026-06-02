package scanner

import "testing"

func TestValidateJobTargetsAllowsContainedCIDRsAndHosts(t *testing.T) {
	job := ScanJob{
		AllowedCIDRs: []string{"192.168.10.0/24"},
		Targets:      []string{"192.168.10.0/25", "192.168.10.20"},
	}
	if err := ValidateJobTargets(job); err != nil {
		t.Fatalf("expected valid targets: %v", err)
	}
}

func TestValidateJobTargetsRejectsOutsideCIDR(t *testing.T) {
	job := ScanJob{
		AllowedCIDRs: []string{"192.168.10.0/24"},
		Targets:      []string{"192.168.11.20"},
	}
	if err := ValidateJobTargets(job); err == nil {
		t.Fatal("expected outside target to be rejected")
	}
}

func TestValidateJobTargetsRejectsIPv6(t *testing.T) {
	job := ScanJob{
		AllowedCIDRs: []string{"192.168.10.0/24"},
		Targets:      []string{"2001:db8::1"},
	}
	if err := ValidateJobTargets(job); err == nil {
		t.Fatal("expected IPv6 target to be rejected")
	}
}
