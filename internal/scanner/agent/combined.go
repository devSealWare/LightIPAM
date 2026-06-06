package agent

import (
	"context"
	"fmt"
	"net/netip"

	"github.com/devSealWare/LightIPAM/internal/scanner"
)

// CombinedDiscoverer runs the full picture for a host in one job: a deep nmap
// scan (all ports, service + OS detection) plus an SNMP ARP-cache harvest and an
// SNMP self-inventory of the same targets. nmap is the core — if it fails the
// combined job fails — but the two SNMP passes are best-effort enrichment: a
// device that does not answer SNMP is *ignored*, not failed, so a combined scan
// of a plain host still succeeds with whatever nmap found.
//
// Observations from all three backends are merged per IP (see mergeObservations)
// so a host's services, OS, MAC, and identity land on one record rather than
// three. SNMP only queries single-host targets; CIDR targets are scanned by nmap
// and skipped (ignored) for SNMP, since SNMP must be pointed at a specific device.
type CombinedDiscoverer struct {
	nmap Discoverer
	snmp Discoverer
}

// NewCombinedDiscoverer composes the nmap and SNMP backends into the combined
// discoverer. Both are taken as the Discoverer interface so tests can inject
// fakes without nmap or a real SNMP device.
func NewCombinedDiscoverer(nmap, snmp Discoverer) *CombinedDiscoverer {
	return &CombinedDiscoverer{nmap: nmap, snmp: snmp}
}

// Discover runs the deep nmap scan, then the two best-effort SNMP passes, and
// returns the merged observations. The returned error is non-nil only when the
// core nmap scan itself fails; SNMP failures are folded into the returned scan
// errors as ignored notices.
func (c *CombinedDiscoverer) Discover(ctx context.Context, job scanner.ScanJob) ([]scanner.Observation, []scanner.ScanError, error) {
	// nmap is the core of a combined scan and always runs at full depth.
	nmapJob := job
	nmapJob.Type = scanner.ScanCombined
	nmapJob.Mode = scanner.ModeDeepActive

	observations, notices, err := c.nmap.Discover(ctx, nmapJob)
	if err != nil {
		return nil, nil, err
	}
	if observations == nil {
		observations = []scanner.Observation{}
	}
	if notices == nil {
		notices = []scanner.ScanError{}
	}

	// Best-effort SNMP enrichment of the single-host targets. Neither pass can
	// fail the job; a non-response becomes an ignored notice.
	arpObs, arpNotices := c.runOptional(ctx, job, scanner.ScanARPTable, "ARP harvest")
	observations = append(observations, arpObs...)
	notices = append(notices, arpNotices...)

	invObs, invNotices := c.runOptional(ctx, job, scanner.ScanSNMPInventory, "SNMP inventory")
	observations = append(observations, invObs...)
	notices = append(notices, invNotices...)

	return mergeObservations(observations), notices, nil
}

// runOptional runs one best-effort SNMP sub-scan of the job's single-host targets
// and downgrades every failure to an ignored notice. It returns the observations
// it gathered (possibly none) and the notices describing what was skipped.
func (c *CombinedDiscoverer) runOptional(ctx context.Context, job scanner.ScanJob, scanType scanner.ScanType, label string) ([]scanner.Observation, []scanner.ScanError) {
	hosts := hostTargets(job.Targets)
	if len(hosts) == 0 {
		return nil, []scanner.ScanError{{
			Code:    scanner.CodeScanIgnored,
			Message: label + " skipped: needs single-host targets (SNMP cannot query a CIDR)",
		}}
	}

	sub := job
	sub.Type = scanType
	sub.Mode = scanner.ModeDeepActive // any active mode; SNMP only checks for passive
	sub.Targets = hosts

	obs, errs, err := c.snmp.Discover(ctx, sub)
	if err != nil {
		// A whole-pass failure (e.g. unsupported SNMP version) is ignored, not fatal.
		return nil, []scanner.ScanError{{Code: scanner.CodeScanIgnored, Message: label + " skipped: " + err.Error()}}
	}

	notices := make([]scanner.ScanError, 0, len(errs))
	for _, e := range errs {
		notices = append(notices, scanner.ScanError{
			Code:    scanner.CodeScanIgnored,
			Message: label + " skipped: " + e.Message,
			Target:  e.Target,
		})
	}
	return obs, notices
}

// hostTargets returns the entries of targets that are bare IPv4 addresses. CIDR
// targets are dropped: nmap scans a range, but SNMP must be aimed at one device.
func hostTargets(targets []string) []string {
	hosts := make([]string, 0, len(targets))
	for _, t := range targets {
		if _, err := netip.ParseAddr(t); err == nil {
			hosts = append(hosts, t)
		}
	}
	return hosts
}

// mergeObservations consolidates observations that share an IP into a single
// record, so a combined scan's nmap, ARP, and SNMP findings for one host become
// one observation rather than three. The first observation for an IP forms the
// base (combined runs nmap first, so its richer service/OS data leads); later
// observations fill empty fields, union services by port, and append evidence.
func mergeObservations(in []scanner.Observation) []scanner.Observation {
	order := make([]string, 0, len(in))
	byIP := make(map[string]*scanner.Observation, len(in))
	for _, obs := range in {
		if obs.IP == "" {
			continue
		}
		base, ok := byIP[obs.IP]
		if !ok {
			cp := obs
			// Clone the slices so a later append never mutates the input's backing
			// array (the discoverers may share or reuse it).
			cp.Services = append([]scanner.ServiceObservation(nil), obs.Services...)
			cp.Evidence = append([]scanner.Evidence(nil), obs.Evidence...)
			byIP[obs.IP] = &cp
			order = append(order, obs.IP)
			continue
		}
		mergeInto(base, obs)
	}

	out := make([]scanner.Observation, 0, len(order))
	for _, ip := range order {
		out = append(out, *byIP[ip])
	}
	return out
}

// mergeInto folds add into base: scalar fields are filled only when base lacks
// them (so the richer leading source wins), services are unioned by port, and all
// evidence is kept.
func mergeInto(base *scanner.Observation, add scanner.Observation) {
	if base.MAC == "" {
		base.MAC = add.MAC
	}
	if base.Vendor == "" {
		base.Vendor = add.Vendor
	}
	if base.Hostname == "" {
		base.Hostname = add.Hostname
	}
	if base.OSFamily == "" {
		base.OSFamily = add.OSFamily
	}
	if base.OSDetail == "" {
		base.OSDetail = add.OSDetail
	}
	base.Services = mergeServices(base.Services, add.Services)
	base.Evidence = append(base.Evidence, add.Evidence...)
	if base.ObservedAt.IsZero() {
		base.ObservedAt = add.ObservedAt
	}
}

// mergeServices appends services from b not already present in a, keyed by
// protocol/port so the same open port reported twice is not duplicated.
func mergeServices(a, b []scanner.ServiceObservation) []scanner.ServiceObservation {
	if len(b) == 0 {
		return a
	}
	key := func(s scanner.ServiceObservation) string { return fmt.Sprintf("%s/%d", s.Protocol, s.Port) }
	seen := make(map[string]bool, len(a)+len(b))
	for _, s := range a {
		seen[key(s)] = true
	}
	for _, s := range b {
		if k := key(s); !seen[k] {
			a = append(a, s)
			seen[k] = true
		}
	}
	return a
}
