package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/devSealWare/LightIPAM/internal/auth"
	"github.com/devSealWare/LightIPAM/internal/macaddr"
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
	Vendor            string
	Hostname          string
	OSFamily          string
	OSDetail          string
	VLAN              int
	Services          []DiscoveryService
	Status            string
	ReconcileStatus   string
	Conflict          string
	ImportedAddressID string
	ImportedDeviceID  string
	FirstSeenAt       time.Time
	LastSeenAt        time.Time
}

// DiscoveryImportTarget is a lightweight view of a pending, non-conflicting
// discovery used by the bulk "Import all" flow: just enough to decide whether a
// managed subnet already contains its address and, when none does, to suggest
// one. HasSubnet uses the same longest-prefix `cidr >>=` containment ImportDiscovery
// relies on, so it is the authoritative answer to "can this import without a new
// subnet?". ScannedTargets carries the targets of the scan job that observed the
// host, so a suggested subnet can match the exact network the operator scanned
// rather than guessing a size.
type DiscoveryImportTarget struct {
	ID             string
	IP             string
	VLAN           int
	HasSubnet      bool
	ScannedTargets []string
}

// DiscoveryInput holds the fields recorded from a single observation.
type DiscoveryInput struct {
	JobID    string
	AgentID  string
	IP       string
	MAC      string
	Vendor   string
	Hostname string
	OSFamily string
	OSDetail string
	VLAN     int
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
INSERT INTO scan_discoveries (id, job_id, agent_id, ip, mac, vendor, hostname, os_family, os_detail, vlan, services, reconcile_status, conflict, last_seen_at)
VALUES ($1, $2, $3, $4::inet, $5::macaddr, $6, $7, $8, $9, $10, $11::jsonb, $12, $13, now())
ON CONFLICT (ip) DO UPDATE SET
	job_id = EXCLUDED.job_id,
	agent_id = EXCLUDED.agent_id,
	mac = COALESCE(EXCLUDED.mac, scan_discoveries.mac),
	vendor = CASE WHEN EXCLUDED.vendor <> '' THEN EXCLUDED.vendor ELSE scan_discoveries.vendor END,
	hostname = CASE WHEN EXCLUDED.hostname <> '' THEN EXCLUDED.hostname ELSE scan_discoveries.hostname END,
	os_family = CASE WHEN EXCLUDED.os_family <> '' THEN EXCLUDED.os_family ELSE scan_discoveries.os_family END,
	os_detail = CASE WHEN EXCLUDED.os_detail <> '' THEN EXCLUDED.os_detail ELSE scan_discoveries.os_detail END,
	-- Preserve a known VLAN when a later (non-inventory) source merges onto the same
	-- IP with none, mirroring the service-list merge.
	vlan = CASE WHEN EXCLUDED.vlan <> 0 THEN EXCLUDED.vlan ELSE scan_discoveries.vlan END,
	-- Preserve a richer earlier service list when this observation has none, so a
	-- MAC-only source (SNMP ARP harvest) merging onto the same IP does not wipe
	-- the services an nmap scan recorded. A non-empty list still replaces wholesale.
	services = CASE WHEN jsonb_array_length(EXCLUDED.services) > 0 THEN EXCLUDED.services ELSE scan_discoveries.services END,
	reconcile_status = EXCLUDED.reconcile_status,
	conflict = EXCLUDED.conflict,
	last_seen_at = now(),
	updated_at = now()
RETURNING id, status`,
		id, emptyToNil(input.JobID), emptyToNil(input.AgentID), input.IP, emptyToNil(input.MAC),
		input.Vendor, input.Hostname, input.OSFamily, input.OSDetail, input.VLAN, string(servicesJSON), status, conflict).Scan(&out.ID, &out.ReviewStatus); err != nil {
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
SELECT host(ip.address)
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

// ListPendingImportTargets returns every pending, non-conflicting discovery
// together with whether a managed subnet already contains it. It backs the
// "Import all" flow: targets with HasSubnet can be imported straight away, while
// the rest drive the create-the-missing-subnet prompt. Conflicts are excluded —
// resolving a conflict is an operator decision, never a bulk action.
func (s *Store) ListPendingImportTargets(ctx context.Context) ([]DiscoveryImportTarget, error) {
	rows, err := s.db.Query(ctx, `
SELECT d.id, host(d.ip), d.vlan,
	EXISTS (SELECT 1 FROM subnets s WHERE s.cidr >>= d.ip),
	COALESCE(j.targets, '{}')
FROM scan_discoveries d
LEFT JOIN scan_jobs j ON j.id = d.job_id
WHERE d.status = 'pending' AND d.reconcile_status <> 'conflict'
ORDER BY d.ip`)
	if err != nil {
		return nil, fmt.Errorf("list pending import targets: %w", err)
	}
	defer rows.Close()

	var targets []DiscoveryImportTarget
	for rows.Next() {
		var t DiscoveryImportTarget
		if err := rows.Scan(&t.ID, &t.IP, &t.VLAN, &t.HasSubnet, &t.ScannedTargets); err != nil {
			return nil, fmt.Errorf("scan import target: %w", err)
		}
		targets = append(targets, t)
	}
	return targets, rows.Err()
}

// ListDiscoveries returns discoveries, optionally filtered by review status
// and/or reconciliation status, newest activity first.
func (s *Store) ListDiscoveries(ctx context.Context, status, reconcile string, limit int) ([]Discovery, error) {
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	rows, err := s.db.Query(ctx, `
SELECT d.id, COALESCE(d.job_id, ''), COALESCE(d.agent_id, ''), COALESCE(a.name, ''),
	host(d.ip), COALESCE(d.mac::text, ''), d.vendor, d.hostname, d.os_family, d.os_detail, d.vlan, d.services::text,
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
	host(d.ip), COALESCE(d.mac::text, ''), d.vendor, d.hostname, d.os_family, d.os_detail, d.vlan, d.services::text,
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
// attaches it to a device. The whole import is one transaction. An optional
// name lets the operator label the device at import time (handy when the host
// has no reverse-DNS hostname and would otherwise be named "host-<ip>"); a blank
// name falls back to the hostname / generated name and never clobbers an
// operator-set name on re-import.
func (s *Store) ImportDiscovery(ctx context.Context, id, name string) (Discovery, error) {
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

	if err := backfillSubnetVLAN(ctx, tx, discovery.IP, discovery.VLAN); err != nil {
		return Discovery{}, err
	}

	deviceID, err := importDiscoveryDevice(ctx, tx, discovery, name)
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

// SyncImportedDiscovery refreshes the device an already-imported discovery is
// linked to with the latest merged findings, so successive scans of different
// types accumulate onto one device instead of only the first import's data
// landing. It updates the device's OS guess, open services, and discovery source
// (never clobbering a richer earlier value with an empty one) and attaches any
// newly observed MAC with its vendor. It also backfills the imported address's
// hostname when that address has none yet, so a name learned by a later scan —
// a NetBIOS/mDNS name_lookup or an LLDP/CDP neighbor's system name — reaches a
// host that nmap had imported without one; an existing hostname is left intact.
//
// It is deliberately conservative: it never renames the device (an operator may
// have named it) and creates no new IPAM records. A discovery that is not
// imported, or whose linked device has since been deleted, is a no-op. Callers
// must skip conflicting observations — resolving a conflict is an operator
// decision, not something a re-scan should silently apply.
func (s *Store) SyncImportedDiscovery(ctx context.Context, id string) error {
	discovery, err := s.GetDiscovery(ctx, id)
	if err != nil {
		return err
	}
	if discovery.Status != "imported" || discovery.ImportedDeviceID == "" {
		return nil
	}

	tx, err := s.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin sync: %w", err)
	}
	defer tx.Rollback(ctx)

	var exists bool
	if err := tx.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM devices WHERE id = $1)", discovery.ImportedDeviceID).Scan(&exists); err != nil {
		return fmt.Errorf("look up imported device: %w", err)
	}
	if !exists {
		return nil
	}

	servicesJSON, err := json.Marshal(discovery.Services)
	if err != nil {
		return fmt.Errorf("marshal discovery services: %w", err)
	}
	source := discovery.AgentName
	if source == "" {
		source = "scan"
	}
	if _, err := tx.Exec(ctx, `
UPDATE devices SET
	os_family = CASE WHEN $2 <> '' THEN $2 ELSE os_family END,
	os_detail = CASE WHEN $3 <> '' THEN $3 ELSE os_detail END,
	services = CASE WHEN jsonb_array_length($4::jsonb) > 0 THEN $4::jsonb ELSE services END,
	discovery_source = $5,
	updated_at = now()
WHERE id = $1`, discovery.ImportedDeviceID, discovery.OSFamily, discovery.OSDetail, string(servicesJSON), source); err != nil {
		return fmt.Errorf("sync discovery device: %w", err)
	}

	if discovery.MAC != "" {
		if err := attachDiscoveryMAC(ctx, tx, discovery.ImportedDeviceID, discovery.MAC, discovery.Vendor); err != nil {
			return err
		}
	}

	// Backfill the imported address's hostname when it has none, so a name learned
	// by a later name_lookup / LLDP-CDP scan lands on an nmap-imported host. Never
	// overwrite an existing hostname.
	if discovery.Hostname != "" && discovery.ImportedAddressID != "" {
		if _, err := tx.Exec(ctx, `
UPDATE ip_addresses SET hostname = $2, updated_at = now()
WHERE id = $1 AND hostname = ''`, discovery.ImportedAddressID, discovery.Hostname); err != nil {
			return fmt.Errorf("sync discovery hostname: %w", err)
		}
	}

	// Backfill the containing subnet's VLAN when a later snmp_inventory scan learns
	// one and the subnet has none yet, so VLAN findings reach the Subnets page on a
	// re-scan, not only at first import.
	if err := backfillSubnetVLAN(ctx, tx, discovery.IP, discovery.VLAN); err != nil {
		return err
	}

	return tx.Commit(ctx)
}

// backfillSubnetVLAN sets the VLAN of the subnet containing ip when the scan
// learned one (vlan > 0) and that subnet has none yet. It never overwrites an
// operator-set VLAN. Overlapping subnets are blocked, so at most the one containing
// subnet matches; a VLAN with no managed subnet is a no-op.
func backfillSubnetVLAN(ctx context.Context, tx pgx.Tx, ip string, vlan int) error {
	if vlan <= 0 {
		return nil
	}
	if _, err := tx.Exec(ctx, `
UPDATE subnets SET vlan = $2, updated_at = now()
WHERE vlan IS NULL AND cidr >>= $1::inet`, ip, vlan); err != nil {
		return fmt.Errorf("backfill subnet vlan: %w", err)
	}
	return nil
}

// importDiscoveryDevice creates (or reuses) the device a discovery imports into
// and stamps it with everything the scan exposed: the OS guess, the open
// services, the reporting agent, and — when known — the MAC with its OUI vendor.
// Unlike the earlier behavior, a device is ALWAYS created, even for a MAC-less
// host (e.g. one scanned over bridged networking), so every imported address
// also appears under Devices. The device is reused on re-import, identified
// first by the discovery's prior import, then by the observed MAC.
//
// name is the operator's optional label from the import form. When provided it
// wins, even on re-import (the operator is explicitly renaming). When blank, a
// new device falls back to the hostname or a generated "host-<ip>" name, and an
// existing device keeps whatever name it already has.
func importDiscoveryDevice(ctx context.Context, tx pgx.Tx, discovery Discovery, name string) (string, error) {
	deviceID, err := resolveImportDevice(ctx, tx, discovery)
	if err != nil {
		return "", err
	}

	servicesJSON, err := json.Marshal(discovery.Services)
	if err != nil {
		return "", fmt.Errorf("marshal discovery services: %w", err)
	}
	source := discovery.AgentName
	if source == "" {
		source = "scan"
	}
	manualName := strings.TrimSpace(name)

	if deviceID == "" {
		deviceName := manualName
		if deviceName == "" {
			deviceName = discovery.Hostname
		}
		if deviceName == "" {
			deviceName = "host-" + discovery.IP
		}
		deviceID, err = auth.RandomToken(18)
		if err != nil {
			return "", err
		}
		if _, err := tx.Exec(ctx, `
INSERT INTO devices (id, name, description, os_family, os_detail, services, discovery_source)
VALUES ($1, $2, 'Created from scan discovery', $3, $4, $5::jsonb, $6)`,
			deviceID, deviceName, discovery.OSFamily, discovery.OSDetail, string(servicesJSON), source); err != nil {
			return "", fmt.Errorf("create discovery device: %w", err)
		}
	} else {
		// Refresh the discovered facts on an existing device. OS, services, and
		// source always reflect the latest observation (empty OS values do not
		// clobber an earlier guess; an empty service list does not wipe services a
		// richer earlier scan recorded — a MAC-only ARP/SNMP import onto a device
		// already carrying an nmap service list keeps that list). The name is left
		// untouched unless the operator supplied an explicit one with this import.
		if _, err := tx.Exec(ctx, `
UPDATE devices SET
	name = CASE WHEN $6 <> '' THEN $6 ELSE name END,
	os_family = CASE WHEN $2 <> '' THEN $2 ELSE os_family END,
	os_detail = CASE WHEN $3 <> '' THEN $3 ELSE os_detail END,
	services = CASE WHEN jsonb_array_length($4::jsonb) > 0 THEN $4::jsonb ELSE services END,
	discovery_source = $5,
	updated_at = now()
WHERE id = $1`, deviceID, discovery.OSFamily, discovery.OSDetail, string(servicesJSON), source, manualName); err != nil {
			return "", fmt.Errorf("update discovery device: %w", err)
		}
	}

	if discovery.MAC != "" {
		if err := attachDiscoveryMAC(ctx, tx, deviceID, discovery.MAC, discovery.Vendor); err != nil {
			return "", err
		}
	}
	return deviceID, nil
}

// resolveImportDevice finds an existing device to reuse for an import: the one a
// prior import of this same discovery created, or any device already owning the
// observed MAC. It returns an empty id when a new device should be created.
func resolveImportDevice(ctx context.Context, tx pgx.Tx, discovery Discovery) (string, error) {
	if discovery.ImportedDeviceID != "" {
		var exists bool
		if err := tx.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM devices WHERE id = $1)", discovery.ImportedDeviceID).Scan(&exists); err != nil {
			return "", fmt.Errorf("look up imported device: %w", err)
		}
		if exists {
			return discovery.ImportedDeviceID, nil
		}
	}
	if discovery.MAC != "" {
		var existing string
		err := tx.QueryRow(ctx, "SELECT device_id FROM mac_addresses WHERE address = $1::macaddr", discovery.MAC).Scan(&existing)
		if err == nil && existing != "" {
			return existing, nil
		}
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return "", fmt.Errorf("look up mac: %w", err)
		}
	}
	return "", nil
}

// attachDiscoveryMAC records the observed MAC on the device with its vendor and
// private-rotating flag, if it is not already present. The vendor reported by
// the scanner (nmap's bundled OUI database) is preferred; the app's small
// built-in OUI table is only a fallback when the scan gave no vendor. When the
// MAC is already recorded, an empty stored vendor is backfilled from the scan.
func attachDiscoveryMAC(ctx context.Context, tx pgx.Tx, deviceID, mac, reportedVendor string) error {
	vendor, isPrivate := reportedVendor, false
	if analysis, err := macaddr.Analyze(mac); err == nil {
		mac = analysis.Address
		isPrivate = analysis.IsPrivate
		if vendor == "" {
			vendor = analysis.Vendor
		}
	}
	macID, err := auth.RandomToken(18)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `
INSERT INTO mac_addresses (id, device_id, address, vendor, is_private)
VALUES ($1, $2, $3::macaddr, $4, $5)
ON CONFLICT (address) DO UPDATE SET
	vendor = CASE WHEN mac_addresses.vendor = '' AND EXCLUDED.vendor <> '' THEN EXCLUDED.vendor ELSE mac_addresses.vendor END`,
		macID, deviceID, mac, vendor, isPrivate); err != nil {
		return fmt.Errorf("create discovery mac: %w", err)
	}
	return nil
}

func scanDiscovery(row subnetScanner) (Discovery, error) {
	var d Discovery
	var servicesJSON string
	if err := row.Scan(
		&d.ID, &d.JobID, &d.AgentID, &d.AgentName,
		&d.IP, &d.MAC, &d.Vendor, &d.Hostname, &d.OSFamily, &d.OSDetail, &d.VLAN, &servicesJSON,
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
