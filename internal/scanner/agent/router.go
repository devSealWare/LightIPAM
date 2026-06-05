package agent

import (
	"context"

	"github.com/devSealWare/LightIPAM/internal/scanner"
)

// DiscoveryRouter dispatches a job to a Discoverer chosen by its scan type,
// falling back to a default for any type not explicitly registered. It lets a
// single agent run nmap for active host/service/OS probing and SNMP for
// ARP-table harvesting, selected per job, without the agent core knowing which
// backend handles what.
type DiscoveryRouter struct {
	byType   map[scanner.ScanType]Discoverer
	fallback Discoverer
}

// NewDiscoveryRouter returns a router that sends unregistered scan types to
// fallback (typically the nmap discoverer). fallback may be nil, in which case
// an unregistered type yields an empty, successful result.
func NewDiscoveryRouter(fallback Discoverer) *DiscoveryRouter {
	return &DiscoveryRouter{
		byType:   make(map[scanner.ScanType]Discoverer),
		fallback: fallback,
	}
}

// Register routes the given scan type to d. It returns the router for chaining.
func (r *DiscoveryRouter) Register(t scanner.ScanType, d Discoverer) *DiscoveryRouter {
	r.byType[t] = d
	return r
}

// Discover sends the job to the Discoverer registered for its type, or to the
// fallback. With neither available it reports no observations.
func (r *DiscoveryRouter) Discover(ctx context.Context, job scanner.ScanJob) ([]scanner.Observation, []scanner.ScanError, error) {
	if d, ok := r.byType[job.Type]; ok {
		return d.Discover(ctx, job)
	}
	if r.fallback != nil {
		return r.fallback.Discover(ctx, job)
	}
	return []scanner.Observation{}, []scanner.ScanError{}, nil
}
