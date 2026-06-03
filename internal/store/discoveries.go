package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/devSealWare/LightIPAM/internal/auth"
	"github.com/jackc/pgx/v5"
)

// ErrNoContainingSubnet is returned when a discovery cannot be imported because
// no managed subnet contains its IP address.
var ErrNoContainingSubnet = errors.New("no subnet contains this address")

// DiscoveryService is one open service observed on a discovered host.
type DiscoveryService struct {
	Protocol    string `json:"protocol"`
	Port        int    `json:"port"`
	State       string `json:"state"`
	ServiceName string `json:"service_name,omitempty"`
	Product     string `json:"product,omitempty"`
	Version     string `json:"version,omitempty"`
}

// Reconciliation statuses describe how a discovery compares to existing IPAM
// records. They are independent of the review status (pending/imported/dismissed).
const (
	ReconcileNew      = "new"      // address is not managed yet
	ReconcileMatch    = "match"    // managed and consistent with the observation
	ReconcileConflict = "conflict" // observation disagrees with a managed record
)

// Discovery is a host observed by a scan, awaiting review before it touches the
// IPAM records. It is the review-queue entry between raw scan results and
// managed addresses/devices.
type Discovery struct {
	ID                string
	JobID             string
	AgentID           string
	AgentName         string
	IP                string
	MAC               string
	Hostname          string
	OSFamily          string
	OSDetail          string
	Services          []DiscoveryService
	Status            string
	ReconcileStatus   string
	Conflict          string
	ImportedAddressID string
	ImportedDeviceID  string
	FirstSeenAt       time.Time
	LastSeenAt        time.Time
}

// DiscoveryInput holds the fields recorded from a single observation.
type DiscoveryInput struct {
	JobID    string
	AgentID  string
	IP       string
	MAC      string
	Hostname string
	OSFamily string
	OSDetail string
	Services []DiscoveryService
}

// DiscoveryUpsert reports the persisted state of an observation: its row id, the
// review status (pending/imported/dismissed, preserved across re-scans), and the
// reconciliation classification. The orchestrator uses it to decide whether a
// trusted agent's observation should be auto-imported.
type DiscoveryUpsert struct {
	ID              string
	ReviewStatus    string
	ReconcileStatus string
}

// UpsertDiscovery records (or refreshes) a discovered host keyed by IP. An
// existing row's review status is preserved: imported and dismissed hosts are
// not resurrected to pending when they are seen again. Each observation is
// reconciled against the managed IPAM records (see reconcileDiscovery): the
// resulting status/conflict note is stored, and a matching managed address has
// its last_seen_at refreshed (the only IPAM write a scan performs on its own).
func (s *Store) UpsertDiscovery(ctx context.Context, input DiscoveryInput) (DiscoveryUpsert, error) {
	id, err := auth.RandomToken(18)
	if err != nil {
		return DiscoveryUpsert{}, err
	}
	services := input.Services
	if services == nil {
		services = []DiscoveryService{}
	}
	servicesJSON, err := json.Marshal(services)
	if err != nil {
		return DiscoveryUpsert{}, fmt.Errorf("marshal discovery services: %w", err)
	}

	status, conflict, err := s.reconcileDiscovery(ctx, input.IP, input.MAC)
	if err != nil {
		return DiscoveryUpsert{}, err
	}

	out := DiscoveryUpsert{ReconcileStatus: status}
	if err := s.db.QueryRow(ctx, `
INSERT INTO scan_discoveries (id, job_id, agent_id, ip, mac, hostname, os_family, os_detail, services, reconcile_status, conflict, last_seen_at)
VALUES ($1, $2, $3, $4::inet, $5::macaddr, $6, $7, $8, $9::jsonb, $10, $11, now())
ON CONFLICT (ip) DO UPDATE SET
	job_id = EXCLUDED.job_id,
	agent_id = EXCLUDED.agent_id,
	mac = COALESCE(EXCLUDED.mac, scan_discoveries.mac),
	hostname = CASE WHEN EXCLUDED.hostname <> '' THEN EXCLUDED.hostname ELSE scan_discoveries.hostname END,
	os_family = CASE WHEN EXCLUDED.os_family <> '' THEN EXCLUDED.os_family ELSE scan_discoveries.os_family END,
	os_detail = CASE WHEN EXCLUDED.os_detail <> '' THEN EXCLUDED.os_detail ELSE scan_discoveries.os_detail END,
	services = EXCLUDED.services,
	reconcile_status = EXCLUDED.reconcile_status,
	conflict = EXCLUDED.conflict,
	last_seen_at = now(),
	updated_at = now()
RETURNING id, status`,
		id, emptyToNil(input.JobID), emptyToNil(input.AgentID), input.IP, emptyToNil(input.MAC),
		input.Hostname, input.OSFamily, input.OSDetail, string(servicesJSON), status, conflict).Scan(&out.ID, &out.ReviewStatus); err != nil {
		return DiscoveryUpsert{}, fmt.Errorf("upsert discovery: %w", err)
	}

	if status != ReconcileNew {
		if _, err := s.db.Exec(ctx, "UPDATE ip_addresses SET last_seen_at = now() WHERE address = $1::inet", input.IP); err != nil {
			return DiscoveryUpsert{}, fmt.Errorf("refresh address last_seen: %w", err)
		}
	}
	return out, nil
}

// reconcileDiscovery compares an observation against the managed IPAM records
// and classifies it. It flags a conflict when the observed MAC contradicts the
// MAC already on the address's device, when a responding host is recorded as
// deprecated, or when the observed MAC is already bound to a different address.
func (s *Store) reconcileDiscovery(ctx context.Context, ip, mac string) (status, conflict string, err error) {
	var macArg any
	if mac != "" {
		macArg = mac
	}

	var (
		deviceName string
		state      string
		macCount   int
		macMatch   int
	)
	err = s.db.QueryRow(ctx, `
SELECT COALESCE(d.name, ''), ip.state::text,
	(SELECT count(*) FROM mac_addresses m WHERE m.device_id = ip.device_id),
	(SELECT count(*) FROM mac_addresses m WHERE m.device_id = ip.device_id AND m.address = $2::macaddr)
FROM ip_addresses ip
LEFT JOIN devices d ON d.id = ip.device_id
WHERE ip.address = $1::inet`, ip, macArg).Scan(&deviceName, &state, &macCount, &macMatch)
	if err == pgx.ErrNoRows {
		// The address is not managed. It is still a conflict if this MAC is
		// already bound to a different managed address (possible IP change).
		if macArg != nil {
			var otherIP string
			e := s.db.QueryRow(ctx, `
SELECT ip.address::text
FROM mac_addresses m
JOIN ip_addresses ip ON ip.device_id = m.device_id
WHERE m.address = $1::macaddr AND ip.address <> $2::inet
LIMIT 1`, macArg, ip).Scan(&otherIP)
			if e == nil {
				return ReconcileConflict, "MAC is already recorded on " + otherIP, nil
			}
			if e != pgx.ErrNoRows {
				return "", "", fmt.Errorf("reconcile mac: %w", e)
			}
		}
		return ReconcileNew, "", nil
	}
	if err != nil {
		return "", "", fmt.Errorf("reconcile discovery: %w", err)
	}

	if macArg != nil && macCount > 0 && macMatch == 0 {
		who := deviceName
		if who == "" {
			who = "another device"
		}
		return ReconcileConflict, "Address is assigned to " + who + " with a different MAC", nil
	}
	if state == "deprecated" {
		return ReconcileConflict, "Address is marked deprecated but is responding", nil
	}
	return ReconcileMatch, "", nil
}

// CountPendingDiscoveries returns how many discoveries await review.
func (s *Store) CountPendingDiscoveries(ctx context.Context) (int, error) {
	var count int
	if err := s.db.QueryRow(ctx, "SELECT count(*) FROM scan_discoveries WHERE status = 'pending'").Scan(&count); err != nil {
		return 0, fmt.Errorf("count pending discoveries: %w", err)
	}
	return count, nil
}

// CountUnreviewedConflicts returns how many pending discoveries conflict with a
// managed IPAM record and need attention.
func (s *Store) CountUnreviewedConflicts(ctx context.Context) (int, error) {
	var count int
	if err := s.db.QueryRow(ctx, "SELECT count(*) FROM scan_discoveries WHERE status = 'pending' AND reconcile_status = 'conflict'").Scan(&count); err != nil {
		return 0, fmt.Errorf("count conflict discoveries: %w", err)
	}
	return count, nil
}

// ListDiscoveries returns discoveries, optionally filtered by review status
// and/or reconciliation status, newest activity first.
func (s *Store) ListDiscoveries(ctx context.Context, status, reconcile string, limit int) ([]Discovery, error) {
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	rows, err := s.db.Query(ctx, `
SELECT d.id, COALESCE(d.job_id, ''), COALESCE(d.agent_id, ''), COALESCE(a.name, ''),
	d.ip::text, COALESCE(d.mac::text, ''), d.hostname, d.os_family, d.os_detail, d.services::text,
	d.status, d.reconcile_status, d.conflict, COALESCE(d.imported_address_id, ''), COALESCE(d.imported_device_id, ''), d.first_seen_at, d.last_seen_at
FROM scan_discoveries d
LEFT JOIN scan_agents a ON a.id = d.agent_id
WHERE ($1 = '' OR d.status = $1) AND ($2 = '' OR d.reconcile_status = $2)
ORDER BY d.last_seen_at DESC
LIMIT $3`, status, reconcile, limit)
	if err != nil {
		return nil, fmt.Errorf("list discoveries: %w", err)
	}
	defer rows.Close()

	var discoveries []Discovery
	for rows.Next() {
		discovery, err := scanDiscovery(rows)
		if err != nil {
			return nil, err
		}
		discoveries = append(discoveries, discovery)
	}
	return discoveries, rows.Err()
}

// GetDiscovery loads a single discovery by id.
func (s *Store) GetDiscovery(ctx context.Context, id string) (Discovery, error) {
	discovery, err := scanDiscovery(s.db.QueryRow(ctx, `
SELECT d.id, COALESCE(d.job_id, ''), COALESCE(d.agent_id, ''), COALESCE(a.name, ''),
	d.ip::text, COALESCE(d.mac::text, ''), d.hostname, d.os_family, d.os_detail, d.services::text,
	d.status, d.reconcile_status, d.conflict, COALESCE(d.imported_address_id, ''), COALESCE(d.imported_device_id, ''), d.first_seen_at, d.last_seen_at
FROM scan_discoveries d
LEFT JOIN scan_agents a ON a.id = d.agent_id
WHERE d.id = $1`, id))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Discovery{}, ErrNotFound
		}
		return Discovery{}, err
	}
	return discovery, nil
}

// DismissDiscovery marks a discovery as reviewed and rejected; it will not be
// resurfaced for import even if seen again.
func (s *Store) DismissDiscovery(ctx context.Context, id string) error {
	tag, err := s.db.Exec(ctx, `
UPDATE scan_discoveries SET status = 'dismissed', updated_at = now()
WHERE id = $1 AND status <> 'imported'`, id)
	if err != nil {
		return fmt.Errorf("dismiss discovery: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ImportDiscovery promotes a discovery into the IPAM records: it creates or
// updates the IP address in its containing subnet and, when a MAC is known,
// attaches it to a device. The whole import is one transaction.
func (s *Store) ImportDiscovery(ctx context.Context, id string) (Discovery, error) {
	discovery, err := s.GetDiscovery(ctx, id)
	if err != nil {
		return Discovery{}, err
	}

	tx, err := s.db.Begin(ctx)
	if err != nil {
		return Discovery{}, fmt.Errorf("begin import: %w", err)
	}
	defer tx.Rollback(ctx)

	var subnetID string
	if err := tx.QueryRow(ctx, `
SELECT id FROM subnets WHERE cidr >>= $1::inet ORDER BY masklen(cidr) DESC LIMIT 1`, discovery.IP).Scan(&subnetID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Discovery{}, ErrNoContainingSubnet
		}
		return Discovery{}, fmt.Errorf("find containing subnet: %w", err)
	}

	deviceID, err := importDiscoveryDevice(ctx, tx, discovery)
	if err != nil {
		return Discovery{}, err
	}

	addressID, err := auth.RandomToken(18)
	if err != nil {
		return Discovery{}, err
	}
	var deviceArg any
	if deviceID != "" {
		deviceArg = deviceID
	}
	if err := tx.QueryRow(ctx, `
INSERT INTO ip_addresses (id, subnet_id, device_id, address, state, hostname, notes, last_seen_at)
VALUES ($1, $2, $3, $4::inet, 'assigned', $5, $6, now())
ON CONFLICT (address) DO UPDATE SET
	subnet_id = EXCLUDED.subnet_id,
	device_id = COALESCE(EXCLUDED.device_id, ip_addresses.device_id),
	hostname = CASE WHEN EXCLUDED.hostname <> '' THEN EXCLUDED.hostname ELSE ip_addresses.hostname END,
	last_seen_at = now(),
	updated_at = now()
RETURNING id`,
		addressID, subnetID, deviceArg, discovery.IP, discovery.Hostname, "Imported from scan discovery").Scan(&addressID); err != nil {
		return Discovery{}, fmt.Errorf("import address: %w", err)
	}

	if _, err := tx.Exec(ctx, `
UPDATE scan_discoveries
SET status = 'imported', imported_address_id = $2, imported_device_id = $3, updated_at = now()
WHERE id = $1`, discovery.ID, addressID, emptyToNil(deviceID)); err != nil {
		return Discovery{}, fmt.Errorf("mark discovery imported: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return Discovery{}, fmt.Errorf("commit import: %w", err)
	}
	return s.GetDiscovery(ctx, id)
}

// importDiscoveryDevice reuses an existing device that already owns the MAC, or
// creates a new device plus MAC record. Returns an empty id when no MAC is known.
func importDiscoveryDevice(ctx context.Context, tx pgx.Tx, discovery Discovery) (string, error) {
	if discovery.MAC == "" {
		return "", nil
	}

	var existing string
	err := tx.QueryRow(ctx, "SELECT device_id FROM mac_addresses WHERE address = $1::macaddr", discovery.MAC).Scan(&existing)
	if err == nil && existing != "" {
		return existing, nil
	}
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return "", fmt.Errorf("look up mac: %w", err)
	}

	name := discovery.Hostname
	if name == "" {
		name = "host-" + discovery.IP
	}
	deviceID, err := auth.RandomToken(18)
	if err != nil {
		return "", err
	}
	if _, err := tx.Exec(ctx, `
INSERT INTO devices (id, name, description)
VALUES ($1, $2, 'Created from scan discovery')`, deviceID, name); err != nil {
		return "", fmt.Errorf("create discovery device: %w", err)
	}

	macID, err := auth.RandomToken(18)
	if err != nil {
		return "", err
	}
	if _, err := tx.Exec(ctx, `
INSERT INTO mac_addresses (id, device_id, address)
VALUES ($1, $2, $3::macaddr)
ON CONFLICT (address) DO NOTHING`, macID, deviceID, discovery.MAC); err != nil {
		return "", fmt.Errorf("create discovery mac: %w", err)
	}
	return deviceID, nil
}

func scanDiscovery(row subnetScanner) (Discovery, error) {
	var d Discovery
	var servicesJSON string
	if err := row.Scan(
		&d.ID, &d.JobID, &d.AgentID, &d.AgentName,
		&d.IP, &d.MAC, &d.Hostname, &d.OSFamily, &d.OSDetail, &servicesJSON,
		&d.Status, &d.ReconcileStatus, &d.Conflict, &d.ImportedAddressID, &d.ImportedDeviceID, &d.FirstSeenAt, &d.LastSeenAt,
	); err != nil {
		return Discovery{}, fmt.Errorf("scan discovery: %w", err)
	}
	if servicesJSON != "" {
		if err := json.Unmarshal([]byte(servicesJSON), &d.Services); err != nil {
			return Discovery{}, fmt.Errorf("decode discovery services: %w", err)
		}
	}
	return d, nil
}
