package agent

import (
	"context"
	"errors"
	"testing"

	"github.com/devSealWare/LightIPAM/internal/scanner"
)

func dhcpJob(targets ...string) scanner.ScanJob {
	if len(targets) == 0 {
		targets = []string{"192.168.1.0/24"}
	}
	return scanner.ScanJob{
		ID:           "job-dhcp",
		AgentID:      "agent-1",
		Type:         scanner.ScanDHCPLeases,
		Mode:         scanner.ModeStandardActive,
		AllowedCIDRs: []string{"192.168.1.0/24"},
		Targets:      targets,
	}
}

func dhcpWith(format string, data []byte) *DHCPDiscoverer {
	d := NewDHCPDiscoverer(DHCPConfig{LeaseFile: "fixture", Format: format})
	d.read = func() ([]byte, error) { return data, nil }
	return d
}

const dnsmasqLeases = `1700000000 b8:27:eb:00:11:22 192.168.1.50 raspberrypi 01:b8:27:eb:00:11:22
1700000000 aa:bb:cc:dd:ee:ff 192.168.1.51 * *
0 11:22:33:44:55:66 10.0.0.9 outsider *
`

func TestDHCPDnsmasqParseAndFilter(t *testing.T) {
	d := dhcpWith("dnsmasq", []byte(dnsmasqLeases))
	obs, errs, err := d.Discover(context.Background(), dhcpJob())
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %+v", errs)
	}
	// 10.0.0.9 is outside the target range and must be dropped.
	if len(obs) != 2 {
		t.Fatalf("got %d observations, want 2: %+v", len(obs), obs)
	}
	if obs[0].IP != "192.168.1.50" || obs[0].MAC != "b8:27:eb:00:11:22" || obs[0].Hostname != "raspberrypi" {
		t.Errorf("obs[0] = %+v", obs[0])
	}
	if obs[0].Evidence[0].Source != "dhcp" {
		t.Errorf("expected dhcp evidence, got %+v", obs[0].Evidence)
	}
	// "*" hostname is treated as unknown.
	if obs[1].IP != "192.168.1.51" || obs[1].Hostname != "" {
		t.Errorf("obs[1] hostname should be empty for '*', got %+v", obs[1])
	}
}

const iscLeases = `# comment
lease 192.168.1.50 {
  starts 4 2023/11/16 00:00:00;
  ends 4 2023/11/16 12:00:00;
  binding state active;
  hardware ethernet b8:27:eb:00:11:22;
  client-hostname "raspberrypi";
}
lease 192.168.1.60 {
  binding state free;
  hardware ethernet de:ad:be:ef:00:01;
}
lease 192.168.1.50 {
  ends 4 2023/11/16 18:00:00;
  binding state active;
  hardware ethernet b8:27:eb:00:11:99;
  client-hostname "pi-renamed";
}
`

func TestDHCPISCParseActiveLastWins(t *testing.T) {
	d := dhcpWith("isc", []byte(iscLeases))
	obs, _, err := d.Discover(context.Background(), dhcpJob())
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	// 192.168.1.60 is free (not active) → dropped; 192.168.1.50 appears twice and
	// the last active block wins.
	if len(obs) != 1 {
		t.Fatalf("got %d observations, want 1 (active, last-wins): %+v", len(obs), obs)
	}
	o := obs[0]
	if o.IP != "192.168.1.50" || o.MAC != "b8:27:eb:00:11:99" || o.Hostname != "pi-renamed" {
		t.Errorf("obs = %+v", o)
	}
	if o.Evidence[0].Summary == "DHCP lease (active)" {
		t.Errorf("expected an expiry in the evidence, got %q", o.Evidence[0].Summary)
	}
}

func TestDHCPAutoDetectsFormat(t *testing.T) {
	if obs, _, _ := dhcpWith("", []byte(iscLeases)).Discover(context.Background(), dhcpJob()); len(obs) != 1 {
		t.Fatalf("auto-detect failed to parse ISC: got %+v", obs)
	}
	if obs, _, _ := dhcpWith("auto", []byte(dnsmasqLeases)).Discover(context.Background(), dhcpJob()); len(obs) != 2 {
		t.Fatalf("auto-detect failed to parse dnsmasq: got %+v", obs)
	}
}

func TestDHCPUnconfiguredIsNotice(t *testing.T) {
	d := NewDHCPDiscoverer(DHCPConfig{}) // no lease file
	obs, errs, err := d.Discover(context.Background(), dhcpJob())
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if len(obs) != 0 {
		t.Fatalf("expected no observations when unconfigured, got %+v", obs)
	}
	if len(errs) != 1 || errs[0].Code != "dhcp_unconfigured" {
		t.Fatalf("expected a dhcp_unconfigured notice, got %+v", errs)
	}
}

func TestDHCPReadErrorIsNotice(t *testing.T) {
	d := NewDHCPDiscoverer(DHCPConfig{LeaseFile: "fixture"})
	d.read = func() ([]byte, error) { return nil, errors.New("permission denied") }
	obs, errs, err := d.Discover(context.Background(), dhcpJob())
	if err != nil {
		t.Fatalf("Discover should not hard-fail on a read error: %v", err)
	}
	if len(obs) != 0 {
		t.Fatalf("expected no observations, got %+v", obs)
	}
	if len(errs) != 1 || errs[0].Code != "dhcp_failed" {
		t.Fatalf("expected a dhcp_failed notice, got %+v", errs)
	}
}

func TestDHCPPassiveShortCircuits(t *testing.T) {
	called := false
	d := dhcpWith("dnsmasq", []byte(dnsmasqLeases))
	d.read = func() ([]byte, error) { called = true; return []byte(dnsmasqLeases), nil }
	job := dhcpJob()
	job.Mode = scanner.ModePassive
	obs, errs, err := d.Discover(context.Background(), job)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if called {
		t.Errorf("passive scan should not read the lease file")
	}
	if len(obs) != 0 || len(errs) != 0 {
		t.Errorf("passive scan should report nothing, got %d obs / %d errs", len(obs), len(errs))
	}
}

func TestDHCPSingleHostTargetScope(t *testing.T) {
	// A combined scan passes single-host targets; only that host's lease is emitted.
	d := dhcpWith("dnsmasq", []byte(dnsmasqLeases))
	obs, _, err := d.Discover(context.Background(), dhcpJob("192.168.1.51"))
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if len(obs) != 1 || obs[0].IP != "192.168.1.51" {
		t.Fatalf("expected only the targeted host's lease, got %+v", obs)
	}
}
