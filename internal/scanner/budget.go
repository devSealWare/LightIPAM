package scanner

import (
	"net"
	"strings"
	"time"
)

// Scan budget tuning. A scan's per-host timeout (ScanJob.TimeoutSeconds) bounds
// nmap's --host-timeout; these constants turn that per-host budget into the total
// time the whole job is allowed.
const (
	// scanGrace is slack beyond the summed per-host budgets so nmap's own
	// --host-timeout fires first and nmap is never hard-killed mid-write.
	scanGrace = 30 * time.Second
	// hostDiscoveryAllowance covers the agent's separate stage-1 host-discovery
	// sweep, which runs once for the whole target set before per-host probing.
	hostDiscoveryAllowance = 2 * time.Minute
	// maxScanBudget caps the total so a huge range cannot request an unbounded
	// deadline. Generous on purpose: a deep all-port sweep of many live hosts is
	// slow, and cutting it short is what surfaced as "context deadline exceeded".
	maxScanBudget = 4 * time.Hour
)

// EstimateTargetHosts is an upper bound on the hosts the targets expand to: a
// bare IP counts as one, a CIDR as its address count. The floor of one keeps a
// single target from collapsing the budget.
func EstimateTargetHosts(targets []string) int {
	total := 0
	for _, t := range targets {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}
		if _, ipnet, err := net.ParseCIDR(t); err == nil {
			ones, bits := ipnet.Mask.Size()
			total += 1 << uint(bits-ones)
		} else {
			total++
		}
	}
	if total < 1 {
		return 1
	}
	return total
}

// ScanBudget returns how long to allow a whole scan job, given its per-host
// timeout and targets: the per-host budget times the (estimated) host count, plus
// an allowance for the host-discovery stage and grace, capped at maxScanBudget. A
// non-positive perHostSeconds yields 0, meaning "no supervising deadline".
//
// Both the agent (supervising the discoverer) and the app (bounding the dispatch
// HTTP call) derive their deadline from this, so the app always outlasts the
// agent's own budget instead of giving up on a long multi-host scan early.
func ScanBudget(perHostSeconds int, targets []string) time.Duration {
	if perHostSeconds <= 0 {
		return 0
	}
	perHost := time.Duration(perHostSeconds) * time.Second
	hosts := EstimateTargetHosts(targets)
	// Guard against overflow on very large ranges before multiplying.
	if hosts > int(maxScanBudget/perHost) {
		return maxScanBudget
	}
	budget := perHost*time.Duration(hosts) + hostDiscoveryAllowance + scanGrace
	if budget > maxScanBudget {
		return maxScanBudget
	}
	return budget
}
