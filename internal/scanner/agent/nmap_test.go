package agent

import (
	"context"
	"strings"
	"testing"

	"github.com/devSealWare/LightIPAM/internal/scanner"
)

func argsContain(args []string, want string) bool {
	for _, a := range args {
		if a == want {
			return true
		}
	}
	return false
}

func TestNmapArgsPassiveSkipsScan(t *testing.T) {
	job := validJob()
	job.Mode = scanner.ModePassive
	_, active, err := nmapArgs(job, EgressOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if active {
		t.Fatal("passive mode must not run nmap")
	}
}

func TestNmapArgsHostDiscoveryUsesPingSweep(t *testing.T) {
	job := validJob()
	job.Type = scanner.ScanHostDiscovery
	job.Mode = scanner.ModeLightActive
	args, active, err := nmapArgs(job, EgressOptions{})
	if err != nil || !active {
		t.Fatalf("expected active host discovery, err=%v active=%v", err, active)
	}
	if !argsContain(args, "-sn") {
		t.Fatalf("expected -sn ping sweep, got %v", args)
	}
	if argsContain(args, "-O") || argsContain(args, "-sV") {
		t.Fatalf("host discovery must not probe ports/OS, got %v", args)
	}
	// Targets must come last, after the option terminator.
	if args[len(args)-1] != job.Targets[0] {
		t.Fatalf("expected target last, got %v", args)
	}
	if !argsContain(args, "--") {
		t.Fatal("expected -- option terminator before targets")
	}
}

func TestNmapArgsDeepCombinedProbesEveryPort(t *testing.T) {
	job := validJob()
	job.Type = scanner.ScanCombined
	job.Mode = scanner.ModeDeepActive
	args, active, err := nmapArgs(job, EgressOptions{})
	if err != nil || !active {
		t.Fatalf("expected active scan, err=%v active=%v", err, active)
	}
	for _, want := range []string{"-sV", "-O", "-p-", "--version-all"} {
		if !argsContain(args, want) {
			t.Fatalf("expected %q in deep combined args, got %v", want, args)
		}
	}
	if argsContain(args, "--top-ports") {
		t.Fatalf("deep mode scans every port (-p-), not the top ports, got %v", args)
	}
}

func TestNmapArgsServiceDetectionDepthByMode(t *testing.T) {
	cases := []struct {
		mode       scanner.ScanMode
		wantPort   string // expected port-selection flag
		wantVerAll bool
		denyPort   string // port flag that must NOT appear
	}{
		{scanner.ModeLightActive, "--top-ports", false, "-p-"},
		{scanner.ModeStandardActive, "--top-ports", true, "-p-"},
		{scanner.ModeDeepActive, "-p-", true, "--top-ports"},
	}
	for _, tc := range cases {
		t.Run(string(tc.mode), func(t *testing.T) {
			job := validJob()
			job.Type = scanner.ScanServiceDetect
			job.Mode = tc.mode
			args, active, err := nmapArgs(job, EgressOptions{})
			if err != nil || !active {
				t.Fatalf("expected active scan, err=%v active=%v", err, active)
			}
			if !argsContain(args, "-sV") {
				t.Fatalf("service detection must run -sV, got %v", args)
			}
			if !argsContain(args, tc.wantPort) {
				t.Fatalf("mode %s: expected port flag %q, got %v", tc.mode, tc.wantPort, args)
			}
			if argsContain(args, tc.denyPort) {
				t.Fatalf("mode %s: did not expect %q, got %v", tc.mode, tc.denyPort, args)
			}
			if got := argsContain(args, "--version-all"); got != tc.wantVerAll {
				t.Fatalf("mode %s: --version-all present=%v, want %v (args %v)", tc.mode, got, tc.wantVerAll, args)
			}
			// Service detection never fingerprints the OS; that is the os_probe type.
			if argsContain(args, "-O") {
				t.Fatalf("service detection must not run -O, got %v", args)
			}
		})
	}
}

func TestNmapArgsLightOSProbeIsOSOnly(t *testing.T) {
	job := validJob()
	job.Type = scanner.ScanOSProbe
	job.Mode = scanner.ModeLightActive
	args, active, err := nmapArgs(job, EgressOptions{})
	if err != nil || !active {
		t.Fatalf("expected active scan, err=%v active=%v", err, active)
	}
	if !argsContain(args, "-O") {
		t.Fatalf("os probe must run -O, got %v", args)
	}
	if argsContain(args, "-sV") {
		t.Fatalf("light os probe should be OS-only (no -sV), got %v", args)
	}
}

func TestNmapArgsRespectsRateLimit(t *testing.T) {
	job := validJob()
	job.Mode = scanner.ModeStandardActive
	job.RateLimit = scanner.RateLimit{ProbesPerSecond: 25, Concurrency: 4}
	args, _, err := nmapArgs(job, EgressOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !argsContain(args, "--max-rate") || !argsContain(args, "25") {
		t.Fatalf("expected --max-rate 25, got %v", args)
	}
	if !argsContain(args, "--max-parallelism") || !argsContain(args, "4") {
		t.Fatalf("expected --max-parallelism 4, got %v", args)
	}
}

func TestNmapArgsPinsEgressWhenConfigured(t *testing.T) {
	job := validJob()
	job.Mode = scanner.ModeStandardActive
	job.Type = scanner.ScanCombined
	egress := EgressOptions{Interface: "eth1", SourceIP: "192.168.0.250"}
	args, active, err := nmapArgs(job, egress)
	if err != nil || !active {
		t.Fatalf("expected active scan, err=%v active=%v", err, active)
	}
	for _, want := range []string{"-e", "eth1", "-S", "192.168.0.250"} {
		if !argsContain(args, want) {
			t.Fatalf("expected egress pin %q in args, got %v", want, args)
		}
	}
	// The pin must precede the option terminator so it applies to the scan.
	for i, a := range args {
		if a == "--" {
			rest := args[:i]
			if !argsContain(rest, "-e") || !argsContain(rest, "-S") {
				t.Fatalf("egress flags must come before --, got %v", args)
			}
			break
		}
	}
}

func TestNmapArgsNoEgressByDefault(t *testing.T) {
	job := validJob()
	job.Mode = scanner.ModeStandardActive
	args, _, err := nmapArgs(job, EgressOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if argsContain(args, "-e") || argsContain(args, "-S") {
		t.Fatalf("expected no egress pin without configuration, got %v", args)
	}
}

const sampleNmapXML = `<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="192.168.10.20" addrtype="ipv4"/>
    <address addr="AA:BB:CC:DD:EE:FF" addrtype="mac" vendor="Acme"/>
    <hostnames><hostname name="nas.local" type="PTR"/></hostnames>
    <ports>
      <port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="9.0"/></port>
      <port protocol="tcp" portid="23"><state state="closed"/><service name="telnet"/></port>
    </ports>
    <os><osmatch name="Linux 5.15" accuracy="98"><osclass osfamily="Linux"/></osmatch></os>
  </host>
  <host>
    <status state="down"/>
    <address addr="192.168.10.21" addrtype="ipv4"/>
  </host>
</nmaprun>`

func TestParseNmapXML(t *testing.T) {
	observations, err := parseNmapXML([]byte(sampleNmapXML))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(observations) != 1 {
		t.Fatalf("expected 1 up host, got %d", len(observations))
	}
	obs := observations[0]
	if obs.IP != "192.168.10.20" {
		t.Fatalf("unexpected ip %q", obs.IP)
	}
	if obs.MAC != "AA:BB:CC:DD:EE:FF" {
		t.Fatalf("unexpected mac %q", obs.MAC)
	}
	if obs.Hostname != "nas.local" {
		t.Fatalf("unexpected hostname %q", obs.Hostname)
	}
	if obs.OSFamily != "Linux" || !strings.Contains(obs.OSDetail, "Linux 5.15") {
		t.Fatalf("unexpected os %q/%q", obs.OSFamily, obs.OSDetail)
	}
	if len(obs.Services) != 1 || obs.Services[0].Port != 22 {
		t.Fatalf("expected only the open port 22, got %+v", obs.Services)
	}
	if len(obs.Evidence) != 1 || !strings.Contains(obs.Evidence[0].Summary, "Acme") {
		t.Fatalf("expected MAC vendor evidence, got %+v", obs.Evidence)
	}
	if obs.Vendor != "Acme" {
		t.Fatalf("expected structured MAC vendor %q, got %q", "Acme", obs.Vendor)
	}
}

func TestParseNmapXMLEmpty(t *testing.T) {
	observations, err := parseNmapXML(nil)
	if err != nil {
		t.Fatalf("parse empty: %v", err)
	}
	if len(observations) != 0 {
		t.Fatalf("expected no observations, got %d", len(observations))
	}
}

// fakeDiscoverer lets us exercise the agent's active-scan path without nmap.
type fakeDiscoverer struct {
	observations []scanner.Observation
	err          error
}

func (f fakeDiscoverer) Discover(context.Context, scanner.ScanJob) ([]scanner.Observation, []scanner.ScanError, error) {
	return f.observations, nil, f.err
}

func TestProcessJobRunsDiscovererForActiveModes(t *testing.T) {
	a := New(Config{
		Registration: testRegistration(),
		Discoverer:   fakeDiscoverer{observations: []scanner.Observation{{IP: "192.168.10.20"}}},
	})
	job := validJob()
	job.Mode = scanner.ModeLightActive
	result := a.processJob(context.Background(), job)
	if result.Status != scanner.JobSucceeded {
		t.Fatalf("expected succeeded, got %q", result.Status)
	}
	if len(result.Observations) != 1 {
		t.Fatalf("expected 1 observation from discoverer, got %d", len(result.Observations))
	}
}

func TestProcessJobPassiveStaysNoOp(t *testing.T) {
	a := New(Config{
		Registration: testRegistration(),
		Discoverer:   fakeDiscoverer{observations: []scanner.Observation{{IP: "192.168.10.20"}}},
	})
	job := validJob() // passive
	result := a.processJob(context.Background(), job)
	if result.Status != scanner.JobSucceeded {
		t.Fatalf("expected succeeded, got %q", result.Status)
	}
	if len(result.Observations) != 0 {
		t.Fatalf("passive mode must not invoke the discoverer, got %d observations", len(result.Observations))
	}
}
