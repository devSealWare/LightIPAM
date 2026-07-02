package agent

import (
	"context"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"sync"

	"github.com/devSealWare/LightIPAM/internal/scanner"
)

// enrichWorkers bounds how many hosts the combined scan enriches at once. A large
// live-host set fans its per-host SNMP/name/DNS queries out across this many
// goroutines, so the slow network timeouts overlap instead of running one after
// another, without flooding the network with unbounded concurrency.
const enrichWorkers = 16

// CombinedDiscoverer runs the full picture for a network in one job: a deep nmap
// scan (all ports, service + OS detection) of the job's targets, then a set of
// best-effort enrichment passes against the hosts nmap found alive — an SNMP
// self-inventory, an SNMP ARP-cache harvest, an SNMP LLDP/CDP neighbor harvest, a
// NetBIOS/mDNS name lookup, and a DNS forward/reverse lookup — plus a DHCP lease
// read over the whole target range.
//
// nmap is the core: if it fails the combined job fails. Every enrichment pass is
// best-effort — a host that does not answer SNMP, a name protocol, or DNS (or a
// source that is not configured) is *ignored*, not failed — so a combined scan of
// plain hosts still succeeds with whatever nmap found.
//
// Crucially, the enrichment passes are aimed at the IPs nmap discovered (unioned
// with any single-host targets the operator listed), not just the raw job targets.
// That is what lets a combined scan of a CIDR — the common case — recover MACs and
// SNMP inventory: nmap expands the range into live hosts, then SNMP/names/DNS query
// each of them. Observations from every backend are merged per IP (see
// mergeObservations) so a host's services, OS, MAC, identity, name, VLAN, and any
// neighbors that resolve to it land on one record rather than several.
type CombinedDiscoverer struct {
	nmap  Discoverer
	snmp  Discoverer
	names Discoverer
	dns   Discoverer
	dhcp  Discoverer
}

// NewCombinedDiscoverer composes the nmap core with the SNMP, name, DNS, and DHCP
// backends into the combined discoverer. Each is taken as the Discoverer interface
// so tests can inject fakes without nmap, a real SNMP device, a live host, real
// DNS, or a lease file. The SNMP backend is reused for three passes (inventory,
// ARP, LLDP/CDP).
func NewCombinedDiscoverer(nmap, snmp, names, dns, dhcp Discoverer) *CombinedDiscoverer {
	return &CombinedDiscoverer{nmap: nmap, snmp: snmp, names: names, dns: dns, dhcp: dhcp}
}

// Discover runs the deep nmap scan, then enriches the discovered hosts, and returns
// the merged observations. The returned error is non-nil only when the core nmap
// scan itself fails; every enrichment failure is folded into the returned scan
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

	// Per-host enrichment targets: the hosts nmap found alive, plus any single-host
	// targets the operator listed (a silent gateway/switch may not answer nmap host
	// discovery yet answer SNMP). DHCP is range-scoped and handled separately.
	perHostTargets := unionHosts(observedIPs(observations), hostTargets(job.Targets))

	enrichObs, enrichNotices := c.enrich(ctx, job, perHostTargets)
	observations = append(observations, enrichObs...)
	notices = append(notices, enrichNotices...)

	return mergeObservations(observations), notices, nil
}

// enrich runs the best-effort passes: a DHCP lease read over the whole target
// range, and the per-host SNMP/name/DNS passes against the discovered hosts via a
// bounded worker pool. It returns the gathered observations in a deterministic
// order (per-host findings in host order, then DHCP) so the later merge keeps a
// stable "leading source wins" precedence regardless of goroutine scheduling.
func (c *CombinedDiscoverer) enrich(ctx context.Context, job scanner.ScanJob, hosts []string) ([]scanner.Observation, []scanner.ScanError) {
	nc := &noticeCollector{}

	// DHCP runs once over the whole target range (it reads a file and can report
	// leases for hosts that are currently down), concurrently with the per-host work.
	var dhcpObs []scanner.Observation
	var dhcpWG sync.WaitGroup
	dhcpWG.Add(1)
	go func() {
		defer dhcpWG.Done()
		dhcpObs = c.runPass(ctx, c.dhcp, job, job.Targets, scanner.ScanDHCPLeases, "DHCP leases", nc)
	}()

	perHost := make([][]scanner.Observation, len(hosts))
	if len(hosts) == 0 {
		nc.noteWhole("Per-host enrichment", "no live hosts discovered to query (SNMP, names, DNS)")
	} else {
		sem := make(chan struct{}, enrichWorkers)
		var wg sync.WaitGroup
		for i, host := range hosts {
			if ctx.Err() != nil {
				break
			}
			sem <- struct{}{}
			wg.Add(1)
			go func(i int, host string) {
				defer wg.Done()
				defer func() { <-sem }()
				perHost[i] = c.enrichHost(ctx, job, host, nc)
			}(i, host)
		}
		wg.Wait()
	}

	dhcpWG.Wait()

	out := make([]scanner.Observation, 0)
	for _, obs := range perHost {
		out = append(out, obs...)
	}
	out = append(out, dhcpObs...)
	return out, nc.notices()
}

// enrichHost runs the per-host enrichment passes against one host and returns its
// observations in merge order (inventory, ARP, LLDP/CDP, name, DNS). SNMP is
// short-circuited: the inventory pass runs first, and the ARP and LLDP/CDP passes —
// which use the same SNMP transport — run only when the host actually answered
// SNMP, so a host that ignores SNMP costs one timeout, not three.
func (c *CombinedDiscoverer) enrichHost(ctx context.Context, job scanner.ScanJob, host string, nc *noticeCollector) []scanner.Observation {
	target := []string{host}
	out := make([]scanner.Observation, 0, 4)

	inv := c.runPass(ctx, c.snmp, job, target, scanner.ScanSNMPInventory, "SNMP inventory", nc)
	out = append(out, inv...)
	if len(inv) > 0 {
		// The host answered SNMP, so it is worth harvesting its ARP cache and any
		// LLDP/CDP neighbors it sees (a plain host yields none; a switch/router does).
		out = append(out, c.runPass(ctx, c.snmp, job, target, scanner.ScanARPTable, "ARP harvest", nc)...)
		out = append(out, c.runPass(ctx, c.snmp, job, target, scanner.ScanLLDPCDP, "LLDP/CDP neighbors", nc)...)
	}
	out = append(out, c.runPass(ctx, c.names, job, target, scanner.ScanNameLookup, "name lookup", nc)...)
	out = append(out, c.runPass(ctx, c.dns, job, target, scanner.ScanDNSLookup, "DNS lookup", nc)...)
	return out
}

// runPass runs one best-effort enrichment sub-scan with discoverer d against the
// given targets and downgrades every failure to a notice on nc. A whole-pass error
// (or a non-targeted ScanError such as "DHCP lease file unconfigured") is kept
// verbatim; a per-target ScanError (a single host that did not respond) is counted,
// so the result lists one tidy line per pass instead of one per host. It returns
// the observations the pass gathered (possibly none).
func (c *CombinedDiscoverer) runPass(ctx context.Context, d Discoverer, job scanner.ScanJob, targets []string, scanType scanner.ScanType, label string, nc *noticeCollector) []scanner.Observation {
	if len(targets) == 0 {
		return nil
	}
	sub := job
	sub.Type = scanType
	sub.Mode = scanner.ModeDeepActive // any active mode; these backends only check for passive
	sub.Targets = targets

	obs, errs, err := d.Discover(ctx, sub)
	if err != nil {
		nc.noteWhole(label, err.Error())
		return nil
	}
	for _, e := range errs {
		if strings.TrimSpace(e.Target) != "" {
			nc.noteTarget(label)
		} else {
			nc.noteWhole(label, e.Message)
		}
	}
	return obs
}

// noticeCollector aggregates the best-effort skip notices a combined scan produces
// so the result lists one tidy line per pass rather than one per non-responding
// host. It is safe for concurrent use by the enrichment worker pool. Per-target
// non-responses are counted by pass label; whole-pass conditions (an unconfigured
// source, an unsupported version) are kept verbatim and deduped.
type noticeCollector struct {
	mu        sync.Mutex
	perTarget map[string]int
	wholePass map[string]string // "label\x00message" -> label, for stable de-duped output
}

// noteTarget records that one host did not respond to the named pass.
func (n *noticeCollector) noteTarget(label string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.perTarget == nil {
		n.perTarget = map[string]int{}
	}
	n.perTarget[label]++
}

// noteWhole records a whole-pass condition (kept verbatim, deduped by label+message).
func (n *noticeCollector) noteWhole(label, message string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.wholePass == nil {
		n.wholePass = map[string]string{}
	}
	n.wholePass[label+"\x00"+message] = label
}

// notices renders the collected conditions as ignored scan notices, in a
// deterministic order (whole-pass notices first, then per-pass non-response
// summaries), so output does not depend on goroutine scheduling.
func (n *noticeCollector) notices() []scanner.ScanError {
	n.mu.Lock()
	defer n.mu.Unlock()

	out := make([]scanner.ScanError, 0, len(n.wholePass)+len(n.perTarget))

	wholeKeys := make([]string, 0, len(n.wholePass))
	for k := range n.wholePass {
		wholeKeys = append(wholeKeys, k)
	}
	sort.Strings(wholeKeys)
	for _, k := range wholeKeys {
		label := n.wholePass[k]
		message := strings.SplitN(k, "\x00", 2)[1]
		out = append(out, scanner.ScanError{
			Code:    scanner.CodeScanIgnored,
			Message: label + " skipped: " + message,
		})
	}

	labels := make([]string, 0, len(n.perTarget))
	for label := range n.perTarget {
		labels = append(labels, label)
	}
	sort.Strings(labels)
	for _, label := range labels {
		count := n.perTarget[label]
		host := "host"
		if count != 1 {
			host = "hosts"
		}
		out = append(out, scanner.ScanError{
			Code:    scanner.CodeScanIgnored,
			Message: fmt.Sprintf("%s skipped: %d %s did not respond", label, count, host),
		})
	}
	return out
}

// unionHosts concatenates the two host lists into one, dropping blanks and
// duplicates while preserving first-seen order (nmap-discovered hosts first, then
// any extra operator-listed single-host targets).
func unionHosts(a, b []string) []string {
	seen := make(map[string]bool, len(a)+len(b))
	out := make([]string, 0, len(a)+len(b))
	for _, list := range [][]string{a, b} {
		for _, h := range list {
			if h == "" || seen[h] {
				continue
			}
			seen[h] = true
			out = append(out, h)
		}
	}
	return out
}

// hostTargets returns the entries of targets that are bare IPv4 addresses. CIDR
// targets are dropped here: nmap scans a range, but the per-host enrichment passes
// must be aimed at one device — they reach a range only via the hosts nmap finds.
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
	if base.VLAN == 0 {
		base.VLAN = add.VLAN
	}
	if base.HWSerial == "" {
		base.HWSerial = add.HWSerial
	}
	if base.HWObjectID == "" {
		base.HWObjectID = add.HWObjectID
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
