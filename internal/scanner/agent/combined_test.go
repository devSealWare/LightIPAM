package agent

import (
	"context"
	"errors"
	"testing"

	"github.com/devSealWare/LightIPAM/internal/scanner"
)

// recordingDiscoverer returns scripted results and records the jobs it received,
// so a test can assert on the sub-jobs the combined discoverer builds.
type recordingDiscoverer struct {
	fn   func(job scanner.ScanJob) ([]scanner.Observation, []scanner.ScanError, error)
	jobs []scanner.ScanJob
}

func (r *recordingDiscoverer) Discover(_ context.Context, job scanner.ScanJob) ([]scanner.Observation, []scanner.ScanError, error) {
	r.jobs = append(r.jobs, job)
	return r.fn(job)
}

func combinedJob() scanner.ScanJob {
	return scanner.ScanJob{
		ID:           "job-1",
		AgentID:      "agent-1",
		Type:         scanner.ScanCombined,
		Mode:         scanner.ModeStandardActive, // should be forced to deep internally
		AllowedCIDRs: []string{"192.168.10.0/24"},
		Targets:      []string{"192.168.10.20"},
	}
}

func TestCombinedMergesAllBackends(t *testing.T) {
	nmap := &recordingDiscoverer{fn: func(scanner.ScanJob) ([]scanner.Observation, []scanner.ScanError, error) {
		return []scanner.Observation{{
			IP:       "192.168.10.20",
			OSFamily: "Linux",
			OSDetail: "Linux 5.15",
			Services: []scanner.ServiceObservation{{Protocol: "tcp", Port: 22, State: "open", ServiceName: "ssh"}},
		}}, nil, nil
	}}
	snmp := &recordingDiscoverer{fn: func(job scanner.ScanJob) ([]scanner.Observation, []scanner.ScanError, error) {
		switch job.Type {
		case scanner.ScanARPTable:
			return []scanner.Observation{{IP: "192.168.10.20", MAC: "aa:bb:cc:dd:ee:ff",
				Evidence: []scanner.Evidence{{Source: "snmp", Summary: "arp"}}}}, nil, nil
		case scanner.ScanSNMPInventory:
			return []scanner.Observation{{IP: "192.168.10.20", Hostname: "nas",
				Evidence: []scanner.Evidence{{Source: "snmp", Summary: "inventory"}}}}, nil, nil
		case scanner.ScanLLDPCDP:
			return []scanner.Observation{{IP: "192.168.10.20",
				Evidence: []scanner.Evidence{{Source: "cdp", Summary: "CDP neighbor reported by 192.168.10.20"}}}}, nil, nil
		default:
			t.Fatalf("unexpected snmp sub-job type %q", job.Type)
			return nil, nil, nil
		}
	}}
	names := &recordingDiscoverer{fn: func(scanner.ScanJob) ([]scanner.Observation, []scanner.ScanError, error) {
		return []scanner.Observation{{IP: "192.168.10.20", Hostname: "MYPC",
			Evidence: []scanner.Evidence{{Source: "netbios", Summary: "NetBIOS name: MYPC"}}}}, nil, nil
	}}
	dns := &recordingDiscoverer{fn: func(scanner.ScanJob) ([]scanner.Observation, []scanner.ScanError, error) {
		return []scanner.Observation{{IP: "192.168.10.20", Hostname: "nas.example.com",
			Evidence: []scanner.Evidence{{Source: "dns", Summary: "Reverse DNS (PTR): nas.example.com (forward-confirmed)"}}}}, nil, nil
	}}

	c := NewCombinedDiscoverer(nmap, snmp, names, dns)
	obs, notices, err := c.Discover(context.Background(), combinedJob())
	if err != nil {
		t.Fatalf("combined discover: %v", err)
	}
	if len(notices) != 0 {
		t.Fatalf("expected no notices when every backend answered, got %+v", notices)
	}
	if len(obs) != 1 {
		t.Fatalf("expected the six sources to merge into one observation, got %d: %+v", len(obs), obs)
	}
	got := obs[0]
	if got.IP != "192.168.10.20" {
		t.Fatalf("unexpected ip %q", got.IP)
	}
	if got.MAC != "aa:bb:cc:dd:ee:ff" {
		t.Fatalf("expected MAC merged from ARP, got %q", got.MAC)
	}
	// SNMP inventory merges before the name and DNS lookups, so its hostname leads.
	if got.Hostname != "nas" {
		t.Fatalf("expected hostname merged from inventory, got %q", got.Hostname)
	}
	if got.OSFamily != "Linux" || got.OSDetail != "Linux 5.15" {
		t.Fatalf("expected OS from nmap, got %q/%q", got.OSFamily, got.OSDetail)
	}
	if len(got.Services) != 1 || got.Services[0].Port != 22 {
		t.Fatalf("expected nmap services preserved, got %+v", got.Services)
	}
	if len(got.Evidence) != 5 {
		t.Fatalf("expected evidence from both SNMP passes, the name lookup, DNS, and LLDP/CDP, got %+v", got.Evidence)
	}

	// nmap must be driven at full depth.
	if len(nmap.jobs) != 1 {
		t.Fatalf("expected one nmap sub-job, got %d", len(nmap.jobs))
	}
	if nmap.jobs[0].Mode != scanner.ModeDeepActive || nmap.jobs[0].Type != scanner.ScanCombined {
		t.Fatalf("nmap sub-job should be deep combined, got %q/%q", nmap.jobs[0].Type, nmap.jobs[0].Mode)
	}
	// SNMP runs all three passes (arp + inventory + lldp_cdp), active, against the
	// single-host targets.
	if len(snmp.jobs) != 3 {
		t.Fatalf("expected three SNMP sub-jobs (arp + inventory + lldp_cdp), got %d", len(snmp.jobs))
	}
	for _, j := range snmp.jobs {
		if j.Mode == scanner.ModePassive {
			t.Fatalf("SNMP sub-job must be active, got passive")
		}
		if len(j.Targets) != 1 || j.Targets[0] != "192.168.10.20" {
			t.Fatalf("SNMP sub-job targets should be the single host, got %v", j.Targets)
		}
	}
	// Name lookup runs once, active, against the single-host targets.
	if len(names.jobs) != 1 {
		t.Fatalf("expected one name-lookup sub-job, got %d", len(names.jobs))
	}
	if names.jobs[0].Type != scanner.ScanNameLookup || names.jobs[0].Mode == scanner.ModePassive {
		t.Fatalf("name sub-job should be an active name_lookup, got %q/%q", names.jobs[0].Type, names.jobs[0].Mode)
	}
	if len(names.jobs[0].Targets) != 1 || names.jobs[0].Targets[0] != "192.168.10.20" {
		t.Fatalf("name sub-job targets should be the single host, got %v", names.jobs[0].Targets)
	}
	// DNS lookup runs once, active, against the single-host targets.
	if len(dns.jobs) != 1 {
		t.Fatalf("expected one DNS-lookup sub-job, got %d", len(dns.jobs))
	}
	if dns.jobs[0].Type != scanner.ScanDNSLookup || dns.jobs[0].Mode == scanner.ModePassive {
		t.Fatalf("dns sub-job should be an active dns_lookup, got %q/%q", dns.jobs[0].Type, dns.jobs[0].Mode)
	}
}

func TestCombinedIgnoresSNMPNoResponse(t *testing.T) {
	nmap := &recordingDiscoverer{fn: func(scanner.ScanJob) ([]scanner.Observation, []scanner.ScanError, error) {
		return []scanner.Observation{{IP: "192.168.10.20", OSFamily: "Linux"}}, nil, nil
	}}
	snmp := &recordingDiscoverer{fn: func(job scanner.ScanJob) ([]scanner.Observation, []scanner.ScanError, error) {
		return nil, []scanner.ScanError{{Code: "snmp_failed", Message: "no response", Target: "192.168.10.20"}}, nil
	}}
	names := &recordingDiscoverer{fn: func(job scanner.ScanJob) ([]scanner.Observation, []scanner.ScanError, error) {
		return nil, []scanner.ScanError{{Code: "name_unresolved", Message: "no NetBIOS or mDNS name", Target: "192.168.10.20"}}, nil
	}}
	dns := &recordingDiscoverer{fn: func(job scanner.ScanJob) ([]scanner.Observation, []scanner.ScanError, error) {
		return nil, []scanner.ScanError{{Code: "dns_unresolved", Message: "no PTR record for this address", Target: "192.168.10.20"}}, nil
	}}

	c := NewCombinedDiscoverer(nmap, snmp, names, dns)
	obs, notices, err := c.Discover(context.Background(), combinedJob())
	if err != nil {
		t.Fatalf("combined must not fail when enrichment is silent: %v", err)
	}
	if len(obs) != 1 || obs[0].IP != "192.168.10.20" {
		t.Fatalf("expected the nmap observation to survive, got %+v", obs)
	}
	// One ignored notice per enrichment pass: ARP, inventory, name lookup, DNS, LLDP/CDP.
	if len(notices) != 5 {
		t.Fatalf("expected one ignored notice per enrichment pass, got %+v", notices)
	}
	for _, n := range notices {
		if n.Code != scanner.CodeScanIgnored {
			t.Fatalf("expected ignored code, got %q", n.Code)
		}
	}
}

func TestCombinedNmapFailureFails(t *testing.T) {
	nmap := &recordingDiscoverer{fn: func(scanner.ScanJob) ([]scanner.Observation, []scanner.ScanError, error) {
		return nil, nil, errors.New("nmap boom")
	}}
	snmp := &recordingDiscoverer{fn: func(scanner.ScanJob) ([]scanner.Observation, []scanner.ScanError, error) {
		t.Fatal("SNMP must not run when nmap fails")
		return nil, nil, nil
	}}
	names := &recordingDiscoverer{fn: func(scanner.ScanJob) ([]scanner.Observation, []scanner.ScanError, error) {
		t.Fatal("name lookup must not run when nmap fails")
		return nil, nil, nil
	}}
	dns := &recordingDiscoverer{fn: func(scanner.ScanJob) ([]scanner.Observation, []scanner.ScanError, error) {
		t.Fatal("DNS lookup must not run when nmap fails")
		return nil, nil, nil
	}}

	c := NewCombinedDiscoverer(nmap, snmp, names, dns)
	if _, _, err := c.Discover(context.Background(), combinedJob()); err == nil {
		t.Fatal("expected combined to fail when its core nmap scan fails")
	}
	if len(snmp.jobs) != 0 {
		t.Fatalf("SNMP should not have been dispatched, got %d jobs", len(snmp.jobs))
	}
	if len(names.jobs) != 0 {
		t.Fatalf("name lookup should not have been dispatched, got %d jobs", len(names.jobs))
	}
	if len(dns.jobs) != 0 {
		t.Fatalf("DNS lookup should not have been dispatched, got %d jobs", len(dns.jobs))
	}
}

func TestCombinedSkipsSNMPForCIDRTargets(t *testing.T) {
	nmap := &recordingDiscoverer{fn: func(scanner.ScanJob) ([]scanner.Observation, []scanner.ScanError, error) {
		return []scanner.Observation{{IP: "192.168.10.20"}}, nil, nil
	}}
	snmp := &recordingDiscoverer{fn: func(scanner.ScanJob) ([]scanner.Observation, []scanner.ScanError, error) {
		t.Fatal("SNMP cannot query a CIDR and must be skipped")
		return nil, nil, nil
	}}
	names := &recordingDiscoverer{fn: func(scanner.ScanJob) ([]scanner.Observation, []scanner.ScanError, error) {
		t.Fatal("name lookup cannot query a CIDR and must be skipped")
		return nil, nil, nil
	}}
	dns := &recordingDiscoverer{fn: func(scanner.ScanJob) ([]scanner.Observation, []scanner.ScanError, error) {
		t.Fatal("DNS lookup cannot query a CIDR and must be skipped")
		return nil, nil, nil
	}}

	job := combinedJob()
	job.Targets = []string{"192.168.10.0/24"}

	c := NewCombinedDiscoverer(nmap, snmp, names, dns)
	obs, notices, err := c.Discover(context.Background(), job)
	if err != nil {
		t.Fatalf("combined discover: %v", err)
	}
	if len(obs) != 1 {
		t.Fatalf("expected nmap observation, got %+v", obs)
	}
	if len(snmp.jobs) != 0 {
		t.Fatalf("SNMP should not run for a CIDR target, got %d jobs", len(snmp.jobs))
	}
	if len(names.jobs) != 0 {
		t.Fatalf("name lookup should not run for a CIDR target, got %d jobs", len(names.jobs))
	}
	if len(dns.jobs) != 0 {
		t.Fatalf("DNS lookup should not run for a CIDR target, got %d jobs", len(dns.jobs))
	}
	// One ignored notice per skipped enrichment pass: ARP, inventory, name lookup,
	// DNS, LLDP/CDP.
	if len(notices) != 5 {
		t.Fatalf("expected an ignored notice per skipped enrichment pass, got %+v", notices)
	}
}

func TestMergeObservations(t *testing.T) {
	in := []scanner.Observation{
		{IP: "10.0.0.1", Services: []scanner.ServiceObservation{{Protocol: "tcp", Port: 80}}},
		{IP: "10.0.0.1", MAC: "aa:bb:cc:dd:ee:ff",
			Services: []scanner.ServiceObservation{{Protocol: "tcp", Port: 80}, {Protocol: "tcp", Port: 443}},
			Evidence: []scanner.Evidence{{Source: "snmp", Summary: "x"}}},
		{IP: ""}, // dropped
		{IP: "10.0.0.2", Hostname: "host2"},
	}
	out := mergeObservations(in)
	if len(out) != 2 {
		t.Fatalf("expected 2 merged observations, got %d: %+v", len(out), out)
	}
	if out[0].IP != "10.0.0.1" || out[1].IP != "10.0.0.2" {
		t.Fatalf("expected first-seen order preserved, got %q,%q", out[0].IP, out[1].IP)
	}
	first := out[0]
	if first.MAC != "aa:bb:cc:dd:ee:ff" {
		t.Fatalf("expected MAC filled from the second observation, got %q", first.MAC)
	}
	if len(first.Services) != 2 {
		t.Fatalf("expected services unioned to 2 (80,443) without duplicating 80, got %+v", first.Services)
	}
	if len(first.Evidence) != 1 {
		t.Fatalf("expected evidence carried over, got %+v", first.Evidence)
	}
}
