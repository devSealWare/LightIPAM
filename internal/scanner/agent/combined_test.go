package agent

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/devSealWare/LightIPAM/internal/scanner"
)

// recordingDiscoverer returns scripted results and records the jobs it received,
// so a test can assert on the sub-jobs the combined discoverer builds. It is safe
// for concurrent use because the combined scan enriches hosts in parallel.
type recordingDiscoverer struct {
	fn   func(job scanner.ScanJob) ([]scanner.Observation, []scanner.ScanError, error)
	mu   sync.Mutex
	jobs []scanner.ScanJob
}

func (r *recordingDiscoverer) Discover(_ context.Context, job scanner.ScanJob) ([]scanner.Observation, []scanner.ScanError, error) {
	r.mu.Lock()
	r.jobs = append(r.jobs, job)
	r.mu.Unlock()
	return r.fn(job)
}

// countType returns how many recorded jobs had the given scan type.
func countType(jobs []scanner.ScanJob, t scanner.ScanType) int {
	n := 0
	for _, j := range jobs {
		if j.Type == t {
			n++
		}
	}
	return n
}

// findByIP returns the merged observation for an IP, or false when absent.
func findByIP(obs []scanner.Observation, ip string) (scanner.Observation, bool) {
	for _, o := range obs {
		if o.IP == ip {
			return o, true
		}
	}
	return scanner.Observation{}, false
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
			return []scanner.Observation{{IP: "192.168.10.20", Hostname: "nas", VLAN: 30,
				Evidence: []scanner.Evidence{{Source: "snmp", Summary: "inventory"}}}}, nil, nil
		case scanner.ScanLLDPCDP:
			return []scanner.Observation{{IP: "192.168.10.20",
				Evidence: []scanner.Evidence{{Source: "cdp", Summary: "CDP neighbor reported by 192.168.10.20"}}}}, nil, nil
		default:
			t.Errorf("unexpected snmp sub-job type %q", job.Type)
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
	dhcp := &recordingDiscoverer{fn: func(scanner.ScanJob) ([]scanner.Observation, []scanner.ScanError, error) {
		return []scanner.Observation{{IP: "192.168.10.20", MAC: "aa:bb:cc:dd:ee:ff", Hostname: "nas-dhcp",
			Evidence: []scanner.Evidence{{Source: "dhcp", Summary: "DHCP lease (active)"}}}}, nil, nil
	}}

	c := NewCombinedDiscoverer(nmap, snmp, names, dns, dhcp)
	obs, notices, err := c.Discover(context.Background(), combinedJob())
	if err != nil {
		t.Fatalf("combined discover: %v", err)
	}
	if len(notices) != 0 {
		t.Fatalf("expected no notices when every backend answered, got %+v", notices)
	}
	if len(obs) != 1 {
		t.Fatalf("expected the sources to merge into one observation, got %d: %+v", len(obs), obs)
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
	if got.VLAN != 30 {
		t.Fatalf("expected VLAN merged from inventory, got %d", got.VLAN)
	}
	if got.OSFamily != "Linux" || got.OSDetail != "Linux 5.15" {
		t.Fatalf("expected OS from nmap, got %q/%q", got.OSFamily, got.OSDetail)
	}
	if len(got.Services) != 1 || got.Services[0].Port != 22 {
		t.Fatalf("expected nmap services preserved, got %+v", got.Services)
	}
	if len(got.Evidence) != 6 {
		t.Fatalf("expected evidence from both SNMP passes, the name lookup, DNS, DHCP, and LLDP/CDP, got %+v", got.Evidence)
	}

	// nmap must be driven at full depth.
	if len(nmap.jobs) != 1 {
		t.Fatalf("expected one nmap sub-job, got %d", len(nmap.jobs))
	}
	if nmap.jobs[0].Mode != scanner.ModeDeepActive || nmap.jobs[0].Type != scanner.ScanCombined {
		t.Fatalf("nmap sub-job should be deep combined, got %q/%q", nmap.jobs[0].Type, nmap.jobs[0].Mode)
	}
	// The host answered SNMP, so all three SNMP passes run (inventory + arp + lldp_cdp)
	// against the single discovered host.
	if len(snmp.jobs) != 3 {
		t.Fatalf("expected three SNMP sub-jobs (inventory + arp + lldp_cdp), got %d", len(snmp.jobs))
	}
	for _, j := range snmp.jobs {
		if j.Mode == scanner.ModePassive {
			t.Fatalf("SNMP sub-job must be active, got passive")
		}
		if len(j.Targets) != 1 || j.Targets[0] != "192.168.10.20" {
			t.Fatalf("SNMP sub-job targets should be the single host, got %v", j.Targets)
		}
	}
	if len(names.jobs) != 1 || names.jobs[0].Type != scanner.ScanNameLookup {
		t.Fatalf("expected one name-lookup sub-job, got %+v", names.jobs)
	}
	if len(dns.jobs) != 1 || dns.jobs[0].Type != scanner.ScanDNSLookup {
		t.Fatalf("expected one DNS-lookup sub-job, got %+v", dns.jobs)
	}
	if len(dhcp.jobs) != 1 || dhcp.jobs[0].Type != scanner.ScanDHCPLeases {
		t.Fatalf("expected one DHCP sub-job, got %+v", dhcp.jobs)
	}
}

func TestCombinedShortCircuitsSNMPAndIgnoresSilence(t *testing.T) {
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
	dhcp := &recordingDiscoverer{fn: func(job scanner.ScanJob) ([]scanner.Observation, []scanner.ScanError, error) {
		return nil, []scanner.ScanError{{Code: "dhcp_unconfigured", Message: "no DHCP lease file configured"}}, nil
	}}

	c := NewCombinedDiscoverer(nmap, snmp, names, dns, dhcp)
	obs, notices, err := c.Discover(context.Background(), combinedJob())
	if err != nil {
		t.Fatalf("combined must not fail when enrichment is silent: %v", err)
	}
	if len(obs) != 1 || obs[0].IP != "192.168.10.20" {
		t.Fatalf("expected the nmap observation to survive, got %+v", obs)
	}
	// The host did not answer SNMP, so ARP and LLDP/CDP are short-circuited: only the
	// one inventory probe is dispatched, not three.
	if got := countType(snmp.jobs, scanner.ScanSNMPInventory); got != 1 {
		t.Fatalf("expected one SNMP inventory probe, got %d", got)
	}
	if got := countType(snmp.jobs, scanner.ScanARPTable); got != 0 {
		t.Fatalf("ARP harvest must be skipped for a host that ignores SNMP, got %d", got)
	}
	if got := countType(snmp.jobs, scanner.ScanLLDPCDP); got != 0 {
		t.Fatalf("LLDP/CDP harvest must be skipped for a host that ignores SNMP, got %d", got)
	}
	// Notices are collapsed to one per pass that produced nothing: SNMP inventory,
	// name lookup, DNS lookup (per-target), plus the DHCP whole-pass condition.
	if len(notices) != 4 {
		t.Fatalf("expected four collapsed ignored notices, got %+v", notices)
	}
	for _, n := range notices {
		if n.Code != scanner.CodeScanIgnored {
			t.Fatalf("expected ignored code, got %q (%s)", n.Code, n.Message)
		}
	}
}

func TestCombinedNmapFailureFails(t *testing.T) {
	nmap := &recordingDiscoverer{fn: func(scanner.ScanJob) ([]scanner.Observation, []scanner.ScanError, error) {
		return nil, nil, errors.New("nmap boom")
	}}
	fatalIfCalled := func(label string) func(scanner.ScanJob) ([]scanner.Observation, []scanner.ScanError, error) {
		return func(scanner.ScanJob) ([]scanner.Observation, []scanner.ScanError, error) {
			t.Errorf("%s must not run when nmap fails", label)
			return nil, nil, nil
		}
	}
	snmp := &recordingDiscoverer{fn: fatalIfCalled("SNMP")}
	names := &recordingDiscoverer{fn: fatalIfCalled("name lookup")}
	dns := &recordingDiscoverer{fn: fatalIfCalled("DNS lookup")}
	dhcp := &recordingDiscoverer{fn: fatalIfCalled("DHCP lookup")}

	c := NewCombinedDiscoverer(nmap, snmp, names, dns, dhcp)
	if _, _, err := c.Discover(context.Background(), combinedJob()); err == nil {
		t.Fatal("expected combined to fail when its core nmap scan fails")
	}
	if len(snmp.jobs)+len(names.jobs)+len(dns.jobs)+len(dhcp.jobs) != 0 {
		t.Fatalf("no enrichment should be dispatched when nmap fails")
	}
}

// TestCombinedEnrichesDiscoveredHosts is the regression test for the core fix: a
// combined scan of a CIDR must enrich the hosts nmap discovers (recovering their
// MACs and SNMP inventory), not skip enrichment because the target is a CIDR.
func TestCombinedEnrichesDiscoveredHosts(t *testing.T) {
	nmap := &recordingDiscoverer{fn: func(scanner.ScanJob) ([]scanner.Observation, []scanner.ScanError, error) {
		// nmap expands the CIDR into two live hosts (no MAC — those come from SNMP/ARP).
		return []scanner.Observation{{IP: "192.168.10.20"}, {IP: "192.168.10.21"}}, nil, nil
	}}
	snmp := &recordingDiscoverer{fn: func(job scanner.ScanJob) ([]scanner.Observation, []scanner.ScanError, error) {
		host := job.Targets[0]
		switch job.Type {
		case scanner.ScanSNMPInventory:
			if host == "192.168.10.20" {
				return []scanner.Observation{{IP: host, Hostname: "switch1",
					Evidence: []scanner.Evidence{{Source: "snmp", Summary: "inventory"}}}}, nil, nil
			}
			return nil, []scanner.ScanError{{Code: "snmp_failed", Message: "no response", Target: host}}, nil
		case scanner.ScanARPTable:
			return []scanner.Observation{{IP: host, MAC: "aa:bb:cc:dd:ee:01",
				Evidence: []scanner.Evidence{{Source: "snmp", Summary: "arp"}}}}, nil, nil
		case scanner.ScanLLDPCDP:
			return nil, nil, nil // no neighbors
		default:
			t.Errorf("unexpected snmp type %q", job.Type)
			return nil, nil, nil
		}
	}}
	names := &recordingDiscoverer{fn: func(job scanner.ScanJob) ([]scanner.Observation, []scanner.ScanError, error) {
		host := job.Targets[0]
		if host == "192.168.10.21" {
			return []scanner.Observation{{IP: host, Hostname: "PC21",
				Evidence: []scanner.Evidence{{Source: "netbios", Summary: "NetBIOS name: PC21"}}}}, nil, nil
		}
		return nil, []scanner.ScanError{{Code: "name_unresolved", Target: host}}, nil
	}}
	dns := &recordingDiscoverer{fn: func(job scanner.ScanJob) ([]scanner.Observation, []scanner.ScanError, error) {
		return nil, []scanner.ScanError{{Code: "dns_unresolved", Target: job.Targets[0]}}, nil
	}}
	dhcp := &recordingDiscoverer{fn: func(job scanner.ScanJob) ([]scanner.Observation, []scanner.ScanError, error) {
		if len(job.Targets) != 1 || job.Targets[0] != "192.168.10.0/24" {
			t.Errorf("DHCP should be scoped to the whole range, got %v", job.Targets)
		}
		// A lease for a host nmap did not find alive (it is currently off).
		return []scanner.Observation{{IP: "192.168.10.22", MAC: "aa:bb:cc:dd:ee:22", Hostname: "leased22",
			Evidence: []scanner.Evidence{{Source: "dhcp", Summary: "DHCP lease (active)"}}}}, nil, nil
	}}

	job := combinedJob()
	job.Targets = []string{"192.168.10.0/24"}

	c := NewCombinedDiscoverer(nmap, snmp, names, dns, dhcp)
	obs, notices, err := c.Discover(context.Background(), job)
	if err != nil {
		t.Fatalf("combined discover: %v", err)
	}

	// Inventory runs on both discovered hosts; ARP/LLDP only on the one that answered.
	if got := countType(snmp.jobs, scanner.ScanSNMPInventory); got != 2 {
		t.Fatalf("expected inventory on both discovered hosts, got %d", got)
	}
	if got := countType(snmp.jobs, scanner.ScanARPTable); got != 1 {
		t.Fatalf("expected ARP harvest only on the SNMP-answering host, got %d", got)
	}
	if got := countType(snmp.jobs, scanner.ScanLLDPCDP); got != 1 {
		t.Fatalf("expected LLDP/CDP only on the SNMP-answering host, got %d", got)
	}
	if len(names.jobs) != 2 {
		t.Fatalf("expected name lookup on both discovered hosts, got %d", len(names.jobs))
	}
	if len(dns.jobs) != 2 {
		t.Fatalf("expected DNS lookup on both discovered hosts, got %d", len(dns.jobs))
	}
	if len(dhcp.jobs) != 1 {
		t.Fatalf("expected one DHCP read over the range, got %d", len(dhcp.jobs))
	}

	// .20 gains its MAC (ARP) and identity (inventory); .21 gains a NetBIOS name;
	// .22 comes only from the DHCP lease (nmap never saw it).
	if len(obs) != 3 {
		t.Fatalf("expected 3 merged hosts (.20, .21, .22), got %d: %+v", len(obs), obs)
	}
	if h20, ok := findByIP(obs, "192.168.10.20"); !ok || h20.MAC != "aa:bb:cc:dd:ee:01" || h20.Hostname != "switch1" {
		t.Fatalf(".20 should merge ARP MAC + inventory hostname, got %+v", h20)
	}
	if h21, ok := findByIP(obs, "192.168.10.21"); !ok || h21.Hostname != "PC21" || h21.MAC != "" {
		t.Fatalf(".21 should carry only its NetBIOS name, got %+v", h21)
	}
	if h22, ok := findByIP(obs, "192.168.10.22"); !ok || h22.MAC != "aa:bb:cc:dd:ee:22" || h22.Hostname != "leased22" {
		t.Fatalf(".22 should come from the DHCP lease, got %+v", h22)
	}

	for _, n := range notices {
		if n.Code != scanner.CodeScanIgnored {
			t.Fatalf("enrichment notices must be ignored, got %q (%s)", n.Code, n.Message)
		}
	}
}

// TestCombinedNoLiveHostsSkipsPerHost verifies a dead range short-circuits the
// per-host passes (no SNMP/name/DNS work) while DHCP still reads the lease file
// over the range — leases can name hosts that are currently offline.
func TestCombinedNoLiveHostsSkipsPerHost(t *testing.T) {
	nmap := &recordingDiscoverer{fn: func(scanner.ScanJob) ([]scanner.Observation, []scanner.ScanError, error) {
		return []scanner.Observation{}, nil, nil // nothing alive
	}}
	fatalIfCalled := func(label string) func(scanner.ScanJob) ([]scanner.Observation, []scanner.ScanError, error) {
		return func(scanner.ScanJob) ([]scanner.Observation, []scanner.ScanError, error) {
			t.Errorf("%s must not run when no hosts are alive", label)
			return nil, nil, nil
		}
	}
	snmp := &recordingDiscoverer{fn: fatalIfCalled("SNMP")}
	names := &recordingDiscoverer{fn: fatalIfCalled("name lookup")}
	dns := &recordingDiscoverer{fn: fatalIfCalled("DNS lookup")}
	dhcp := &recordingDiscoverer{fn: func(job scanner.ScanJob) ([]scanner.Observation, []scanner.ScanError, error) {
		return []scanner.Observation{{IP: "192.168.10.50", MAC: "aa:bb:cc:dd:ee:50", Hostname: "offline-host",
			Evidence: []scanner.Evidence{{Source: "dhcp", Summary: "DHCP lease (active)"}}}}, nil, nil
	}}

	job := combinedJob()
	job.Targets = []string{"192.168.10.0/24"}

	c := NewCombinedDiscoverer(nmap, snmp, names, dns, dhcp)
	obs, notices, err := c.Discover(context.Background(), job)
	if err != nil {
		t.Fatalf("combined discover: %v", err)
	}
	if len(snmp.jobs)+len(names.jobs)+len(dns.jobs) != 0 {
		t.Fatalf("per-host enrichment must be skipped when no hosts are alive")
	}
	if len(dhcp.jobs) != 1 {
		t.Fatalf("DHCP should still read the lease file over the range, got %d", len(dhcp.jobs))
	}
	if h, ok := findByIP(obs, "192.168.10.50"); !ok || h.Hostname != "offline-host" {
		t.Fatalf("expected the DHCP lease for the offline host, got %+v", obs)
	}
	// A single informational notice that there were no live hosts to enrich.
	found := false
	for _, n := range notices {
		if n.Code != scanner.CodeScanIgnored {
			t.Fatalf("notices must be ignored, got %q", n.Code)
		}
		found = true
	}
	if !found {
		t.Fatalf("expected an ignored notice that there were no live hosts to enrich")
	}
}

func TestMergeObservations(t *testing.T) {
	in := []scanner.Observation{
		{IP: "10.0.0.1", Services: []scanner.ServiceObservation{{Protocol: "tcp", Port: 80}}},
		{IP: "10.0.0.1", MAC: "aa:bb:cc:dd:ee:ff", VLAN: 40, HWSerial: "CHS-5", HWObjectID: "1.3.6.1.4.1.9",
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
	if first.VLAN != 40 {
		t.Fatalf("expected VLAN filled from the second observation, got %d", first.VLAN)
	}
	if first.HWSerial != "CHS-5" || first.HWObjectID != "1.3.6.1.4.1.9" {
		t.Fatalf("expected hardware identity filled from the SNMP observation, got %q/%q", first.HWSerial, first.HWObjectID)
	}
	if len(first.Services) != 2 {
		t.Fatalf("expected services unioned to 2 (80,443) without duplicating 80, got %+v", first.Services)
	}
	if len(first.Evidence) != 1 {
		t.Fatalf("expected evidence carried over, got %+v", first.Evidence)
	}
}
