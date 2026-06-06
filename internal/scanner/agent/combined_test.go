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
		default:
			t.Fatalf("unexpected snmp sub-job type %q", job.Type)
			return nil, nil, nil
		}
	}}

	c := NewCombinedDiscoverer(nmap, snmp)
	obs, notices, err := c.Discover(context.Background(), combinedJob())
	if err != nil {
		t.Fatalf("combined discover: %v", err)
	}
	if len(notices) != 0 {
		t.Fatalf("expected no notices when every backend answered, got %+v", notices)
	}
	if len(obs) != 1 {
		t.Fatalf("expected the three sources to merge into one observation, got %d: %+v", len(obs), obs)
	}
	got := obs[0]
	if got.IP != "192.168.10.20" {
		t.Fatalf("unexpected ip %q", got.IP)
	}
	if got.MAC != "aa:bb:cc:dd:ee:ff" {
		t.Fatalf("expected MAC merged from ARP, got %q", got.MAC)
	}
	if got.Hostname != "nas" {
		t.Fatalf("expected hostname merged from inventory, got %q", got.Hostname)
	}
	if got.OSFamily != "Linux" || got.OSDetail != "Linux 5.15" {
		t.Fatalf("expected OS from nmap, got %q/%q", got.OSFamily, got.OSDetail)
	}
	if len(got.Services) != 1 || got.Services[0].Port != 22 {
		t.Fatalf("expected nmap services preserved, got %+v", got.Services)
	}
	if len(got.Evidence) != 2 {
		t.Fatalf("expected evidence from both SNMP passes, got %+v", got.Evidence)
	}

	// nmap must be driven at full depth.
	if len(nmap.jobs) != 1 {
		t.Fatalf("expected one nmap sub-job, got %d", len(nmap.jobs))
	}
	if nmap.jobs[0].Mode != scanner.ModeDeepActive || nmap.jobs[0].Type != scanner.ScanCombined {
		t.Fatalf("nmap sub-job should be deep combined, got %q/%q", nmap.jobs[0].Type, nmap.jobs[0].Mode)
	}
	// SNMP runs both passes, active, against the single-host targets.
	if len(snmp.jobs) != 2 {
		t.Fatalf("expected two SNMP sub-jobs (arp + inventory), got %d", len(snmp.jobs))
	}
	for _, j := range snmp.jobs {
		if j.Mode == scanner.ModePassive {
			t.Fatalf("SNMP sub-job must be active, got passive")
		}
		if len(j.Targets) != 1 || j.Targets[0] != "192.168.10.20" {
			t.Fatalf("SNMP sub-job targets should be the single host, got %v", j.Targets)
		}
	}
}

func TestCombinedIgnoresSNMPNoResponse(t *testing.T) {
	nmap := &recordingDiscoverer{fn: func(scanner.ScanJob) ([]scanner.Observation, []scanner.ScanError, error) {
		return []scanner.Observation{{IP: "192.168.10.20", OSFamily: "Linux"}}, nil, nil
	}}
	snmp := &recordingDiscoverer{fn: func(job scanner.ScanJob) ([]scanner.Observation, []scanner.ScanError, error) {
		return nil, []scanner.ScanError{{Code: "snmp_failed", Message: "no response", Target: "192.168.10.20"}}, nil
	}}

	c := NewCombinedDiscoverer(nmap, snmp)
	obs, notices, err := c.Discover(context.Background(), combinedJob())
	if err != nil {
		t.Fatalf("combined must not fail when SNMP is silent: %v", err)
	}
	if len(obs) != 1 || obs[0].IP != "192.168.10.20" {
		t.Fatalf("expected the nmap observation to survive, got %+v", obs)
	}
	if len(notices) != 2 {
		t.Fatalf("expected one ignored notice per SNMP pass, got %+v", notices)
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

	c := NewCombinedDiscoverer(nmap, snmp)
	if _, _, err := c.Discover(context.Background(), combinedJob()); err == nil {
		t.Fatal("expected combined to fail when its core nmap scan fails")
	}
	if len(snmp.jobs) != 0 {
		t.Fatalf("SNMP should not have been dispatched, got %d jobs", len(snmp.jobs))
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

	job := combinedJob()
	job.Targets = []string{"192.168.10.0/24"}

	c := NewCombinedDiscoverer(nmap, snmp)
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
	if len(notices) != 2 {
		t.Fatalf("expected an ignored notice per skipped SNMP pass, got %+v", notices)
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
