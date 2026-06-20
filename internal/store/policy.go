package store

import (
	"context"
	"fmt"
	"time"
)

// Policy finding severities, ranked most → least urgent for display. Kept as
// plain string constants (like the reconcile statuses) so template comparisons
// work directly.
const (
	SeverityCritical = "critical"
	SeverityWarning  = "warning"
	SeverityInfo     = "info"
)

// PolicyFinding is one hygiene problem flagged by a policy/health check. It is
// computed on demand (never stored) and rendered on the /policy page. The type
// lives in store — not app — so the ui templates can render it without an
// app → ui → app import cycle (the same arrangement as ImportResult).
type PolicyFinding struct {
	Check    string // stable check id, e.g. "overlapping_subnets"
	Severity string // one of the Severity* constants
	Title    string // short headline
	Detail   string // human explanation
	Link     string // in-app link to the offending record ("" if none)
}

// PolicyFindingGroup is the set of findings produced by one check, with a
// display label, for the /policy page. A group with no findings renders as a
// clean "all good" row.
type PolicyFindingGroup struct {
	Check    string
	Label    string
	Findings []PolicyFinding
}

// PolicySummary counts findings by severity for the dashboard widget and the
// /policy header.
type PolicySummary struct {
	Critical int
	Warning  int
	Info     int
}

// Total is the combined finding count across all severities.
func (s PolicySummary) Total() int { return s.Critical + s.Warning + s.Info }

// PolicySubnet is the subset of a subnet the overlap check needs.
type PolicySubnet struct {
	ID   string
	Name string
	CIDR string
}

// PolicyRecord is a managed address or device evaluated for staleness. LastSeen
// is nil when the record has never been observed by a scan. Link points at the
// record's in-app page.
type PolicyRecord struct {
	Kind     string // "ip_address" | "device"
	Label    string // the address (host form) or device name
	Context  string // subnet name for an address; empty for a device
	State    string // address state; empty for a device
	LastSeen *time.Time
	Link     string
}

// PolicyDiscoveryRecord is a pending discovery the unmanaged-services check
// inspects: a host seen on the network that is either running services and not
// yet imported, or in conflict with a managed record.
type PolicyDiscoveryRecord struct {
	IP              string
	Hostname        string
	ReconcileStatus string
	Conflict        string
	ServiceCount    int
	Link            string
}

// PolicySubnets returns every subnet's id/name/CIDR for the overlap check.
func (s *Store) PolicySubnets(ctx context.Context) ([]PolicySubnet, error) {
	rows, err := s.db.Query(ctx, `SELECT id, name, cidr::text FROM subnets ORDER BY cidr`)
	if err != nil {
		return nil, fmt.Errorf("policy subnets: %w", err)
	}
	defer rows.Close()
	var out []PolicySubnet
	for rows.Next() {
		var p PolicySubnet
		if err := rows.Scan(&p.ID, &p.Name, &p.CIDR); err != nil {
			return nil, fmt.Errorf("scan policy subnet: %w", err)
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// PolicyAddressRecords returns the managed addresses in an in-use state
// (assigned or reserved) — those expected to correspond to a live host — with
// each address's containing-subnet name and last-seen timestamp, for the stale
// check. Available/deprecated addresses are excluded by design (they are not
// expected to be seen). The Link targets the address's subnet detail page.
func (s *Store) PolicyAddressRecords(ctx context.Context) ([]PolicyRecord, error) {
	rows, err := s.db.Query(ctx, `
SELECT host(ip.address), ip.state::text, COALESCE(sub.name, ''), COALESCE(ip.subnet_id, ''), ip.last_seen_at
FROM ip_addresses ip
LEFT JOIN subnets sub ON sub.id = ip.subnet_id
WHERE ip.state IN ('assigned', 'reserved')
ORDER BY ip.address`)
	if err != nil {
		return nil, fmt.Errorf("policy address records: %w", err)
	}
	defer rows.Close()
	var out []PolicyRecord
	for rows.Next() {
		var (
			rec      PolicyRecord
			subnetID string
		)
		rec.Kind = "ip_address"
		if err := rows.Scan(&rec.Label, &rec.State, &rec.Context, &subnetID, &rec.LastSeen); err != nil {
			return nil, fmt.Errorf("scan policy address: %w", err)
		}
		if subnetID != "" {
			rec.Link = "/subnets/" + subnetID
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}

// PolicyDeviceRecords returns every device that has at least one linked address,
// with the most recent last-seen timestamp across its addresses (nil when none
// of them has ever been seen), for the stale check. A device with no address has
// nothing that can be "seen", so it is excluded.
func (s *Store) PolicyDeviceRecords(ctx context.Context) ([]PolicyRecord, error) {
	rows, err := s.db.Query(ctx, `
SELECT d.id, d.name, max(ip.last_seen_at)
FROM devices d
JOIN ip_addresses ip ON ip.device_id = d.id
GROUP BY d.id, d.name
ORDER BY d.name`)
	if err != nil {
		return nil, fmt.Errorf("policy device records: %w", err)
	}
	defer rows.Close()
	var out []PolicyRecord
	for rows.Next() {
		var (
			rec PolicyRecord
			id  string
		)
		rec.Kind = "device"
		if err := rows.Scan(&id, &rec.Label, &rec.LastSeen); err != nil {
			return nil, fmt.Errorf("scan policy device: %w", err)
		}
		rec.Link = "/devices/" + id
		out = append(out, rec)
	}
	return out, rows.Err()
}

// PolicyDiscoveryRecords returns the pending discoveries that are worth flagging:
// either in conflict with a managed record, or running one or more services
// while not yet imported. The reconcile status is carried straight through so the
// pure check classifies them without re-querying.
func (s *Store) PolicyDiscoveryRecords(ctx context.Context) ([]PolicyDiscoveryRecord, error) {
	rows, err := s.db.Query(ctx, `
SELECT host(ip), hostname, reconcile_status, conflict, jsonb_array_length(services)
FROM scan_discoveries
WHERE status = 'pending' AND (reconcile_status = 'conflict' OR jsonb_array_length(services) > 0)
ORDER BY ip`)
	if err != nil {
		return nil, fmt.Errorf("policy discovery records: %w", err)
	}
	defer rows.Close()
	var out []PolicyDiscoveryRecord
	for rows.Next() {
		var d PolicyDiscoveryRecord
		if err := rows.Scan(&d.IP, &d.Hostname, &d.ReconcileStatus, &d.Conflict, &d.ServiceCount); err != nil {
			return nil, fmt.Errorf("scan policy discovery: %w", err)
		}
		d.Link = "/discoveries"
		out = append(out, d)
	}
	return out, rows.Err()
}
