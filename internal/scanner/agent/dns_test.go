package agent

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/devSealWare/LightIPAM/internal/scanner"
)

// fakeResolver scripts reverse (PTR) and forward (host) lookups by IP/name so the
// DNS discoverer is exercised without touching real DNS.
type fakeResolver struct {
	ptr     map[string][]string // ip -> names
	forward map[string][]string // name -> ips
	err     map[string]error    // ip -> reverse-lookup error
}

func (f fakeResolver) LookupAddr(_ context.Context, addr string) ([]string, error) {
	if err, ok := f.err[addr]; ok {
		return nil, err
	}
	names, ok := f.ptr[addr]
	if !ok {
		return nil, fmt.Errorf("no PTR for %s", addr)
	}
	return names, nil
}

func (f fakeResolver) LookupHost(_ context.Context, host string) ([]string, error) {
	ips, ok := f.forward[host]
	if !ok {
		return nil, fmt.Errorf("no A for %s", host)
	}
	return ips, nil
}

func dnsJob(targets ...string) scanner.ScanJob {
	return scanner.ScanJob{
		ID:           "job-dns",
		AgentID:      "agent-1",
		Type:         scanner.ScanDNSLookup,
		Mode:         scanner.ModeStandardActive,
		AllowedCIDRs: []string{"192.168.1.0/24"},
		Targets:      targets,
	}
}

func TestDNSDiscoverForwardConfirmed(t *testing.T) {
	d := NewDNSDiscoverer(DNSConfig{})
	d.resolve = fakeResolver{
		ptr:     map[string][]string{"192.168.1.5": {"nas.example.com."}},
		forward: map[string][]string{"nas.example.com": {"192.168.1.5"}},
	}

	obs, errs, err := d.Discover(context.Background(), dnsJob("192.168.1.5"))
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if len(errs) != 0 {
		t.Fatalf("expected no errors, got %+v", errs)
	}
	if len(obs) != 1 {
		t.Fatalf("expected one observation, got %d: %+v", len(obs), obs)
	}
	got := obs[0]
	if got.IP != "192.168.1.5" {
		t.Fatalf("ip = %q", got.IP)
	}
	// The trailing dot of the PTR record is trimmed and the FQDN is kept.
	if got.Hostname != "nas.example.com" {
		t.Fatalf("hostname = %q, want nas.example.com", got.Hostname)
	}
	if len(got.Evidence) != 1 || got.Evidence[0].Source != "dns" {
		t.Fatalf("expected one dns evidence entry, got %+v", got.Evidence)
	}
	if !strings.Contains(got.Evidence[0].Summary, "forward-confirmed") {
		t.Fatalf("expected forward-confirmed evidence, got %q", got.Evidence[0].Summary)
	}
}

func TestDNSDiscoverForwardMismatchStillNames(t *testing.T) {
	d := NewDNSDiscoverer(DNSConfig{})
	d.resolve = fakeResolver{
		ptr:     map[string][]string{"192.168.1.6": {"stale.example.com"}},
		forward: map[string][]string{"stale.example.com": {"192.168.1.99"}}, // points elsewhere
	}

	obs, _, err := d.Discover(context.Background(), dnsJob("192.168.1.6"))
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if len(obs) != 1 {
		t.Fatalf("expected one observation, got %+v", obs)
	}
	if obs[0].Hostname != "stale.example.com" {
		t.Fatalf("hostname = %q, want stale.example.com (name kept despite mismatch)", obs[0].Hostname)
	}
	if !strings.Contains(obs[0].Evidence[0].Summary, "did not confirm") {
		t.Fatalf("expected an unconfirmed note, got %q", obs[0].Evidence[0].Summary)
	}
}

func TestDNSDiscoverNoPTRIsUnresolved(t *testing.T) {
	d := NewDNSDiscoverer(DNSConfig{})
	d.resolve = fakeResolver{ptr: map[string][]string{}} // no records

	obs, errs, err := d.Discover(context.Background(), dnsJob("192.168.1.7"))
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if len(obs) != 0 {
		t.Fatalf("expected no observation for a host with no PTR, got %+v", obs)
	}
	if len(errs) != 1 || errs[0].Code != "dns_unresolved" {
		t.Fatalf("expected one dns_unresolved error, got %+v", errs)
	}
}

func TestDNSDiscoverRejectsCIDRTarget(t *testing.T) {
	d := NewDNSDiscoverer(DNSConfig{})
	d.resolve = fakeResolver{ptr: map[string][]string{}}

	obs, errs, err := d.Discover(context.Background(), dnsJob("192.168.1.0/24"))
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if len(obs) != 0 {
		t.Fatalf("expected no observation for a CIDR target, got %+v", obs)
	}
	if len(errs) != 1 || errs[0].Code != "dns_unresolved" {
		t.Fatalf("expected a dns_unresolved notice for the CIDR, got %+v", errs)
	}
}

func TestDNSDiscoverOutOfScopeDropped(t *testing.T) {
	d := NewDNSDiscoverer(DNSConfig{})
	d.resolve = fakeResolver{
		ptr: map[string][]string{"10.0.0.1": {"router.example.com"}},
	}
	// 10.0.0.1 is a valid host but outside the job allowlist; it must be dropped
	// silently (defensive — the protocol already rejects it).
	job := dnsJob("10.0.0.1")
	obs, errs, err := d.Discover(context.Background(), job)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if len(obs) != 0 || len(errs) != 0 {
		t.Fatalf("out-of-scope target should be dropped, got obs=%+v errs=%+v", obs, errs)
	}
}

func TestDNSDiscoverPassiveShortCircuits(t *testing.T) {
	d := NewDNSDiscoverer(DNSConfig{})
	d.resolve = fakeResolver{ptr: map[string][]string{"192.168.1.5": {"x.example.com"}}}

	job := dnsJob("192.168.1.5")
	job.Mode = scanner.ModePassive
	obs, errs, err := d.Discover(context.Background(), job)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if len(obs) != 0 || len(errs) != 0 {
		t.Fatalf("passive scan should yield nothing, got obs=%+v errs=%+v", obs, errs)
	}
}
