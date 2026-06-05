package agent

import (
	"context"
	"testing"

	"github.com/devSealWare/LightIPAM/internal/scanner"
)

// stubDiscoverer records that it ran and returns a tagged observation.
type stubDiscoverer struct {
	tag    string
	called bool
}

func (s *stubDiscoverer) Discover(ctx context.Context, job scanner.ScanJob) ([]scanner.Observation, []scanner.ScanError, error) {
	s.called = true
	return []scanner.Observation{{IP: s.tag}}, []scanner.ScanError{}, nil
}

func TestDiscoveryRouterDispatchesByType(t *testing.T) {
	nmap := &stubDiscoverer{tag: "nmap"}
	snmp := &stubDiscoverer{tag: "snmp"}
	router := NewDiscoveryRouter(nmap).Register(scanner.ScanARPTable, snmp)

	obs, _, err := router.Discover(context.Background(), scanner.ScanJob{Type: scanner.ScanARPTable})
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if !snmp.called || nmap.called {
		t.Fatalf("arp_table should route to snmp only (snmp=%v nmap=%v)", snmp.called, nmap.called)
	}
	if len(obs) != 1 || obs[0].IP != "snmp" {
		t.Fatalf("unexpected observations: %+v", obs)
	}
}

func TestDiscoveryRouterRoutesInventory(t *testing.T) {
	nmap := &stubDiscoverer{tag: "nmap"}
	snmp := &stubDiscoverer{tag: "snmp"}
	router := NewDiscoveryRouter(nmap).
		Register(scanner.ScanARPTable, snmp).
		Register(scanner.ScanSNMPInventory, snmp)

	obs, _, err := router.Discover(context.Background(), scanner.ScanJob{Type: scanner.ScanSNMPInventory})
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if !snmp.called || nmap.called {
		t.Fatalf("snmp_inventory should route to snmp only (snmp=%v nmap=%v)", snmp.called, nmap.called)
	}
	if len(obs) != 1 || obs[0].IP != "snmp" {
		t.Fatalf("unexpected observations: %+v", obs)
	}
}

func TestDiscoveryRouterFallsBack(t *testing.T) {
	nmap := &stubDiscoverer{tag: "nmap"}
	snmp := &stubDiscoverer{tag: "snmp"}
	router := NewDiscoveryRouter(nmap).Register(scanner.ScanARPTable, snmp)

	obs, _, err := router.Discover(context.Background(), scanner.ScanJob{Type: scanner.ScanCombined})
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if !nmap.called || snmp.called {
		t.Fatalf("combined should route to nmap fallback (nmap=%v snmp=%v)", nmap.called, snmp.called)
	}
	if len(obs) != 1 || obs[0].IP != "nmap" {
		t.Fatalf("unexpected observations: %+v", obs)
	}
}

func TestDiscoveryRouterNilFallback(t *testing.T) {
	router := NewDiscoveryRouter(nil)
	obs, scanErrs, err := router.Discover(context.Background(), scanner.ScanJob{Type: scanner.ScanHostDiscovery})
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if len(obs) != 0 || len(scanErrs) != 0 {
		t.Fatalf("nil fallback should yield empty result, got %d obs / %d errs", len(obs), len(scanErrs))
	}
}
