package store

import (
	"context"
	"fmt"

	"github.com/devSealWare/LightIPAM/internal/auth"
	"github.com/jackc/pgx/v5"
)

// CSV import/export (Phase 4.5). Export reuses the list queries where possible;
// addresses get a dedicated cross-subnet query that carries the containing
// subnet's CIDR and the linked device name so an export round-trips back through
// import. Imports are upserts keyed on each object's natural identity (subnet
// CIDR, address, device name) and run in a single transaction, so an import is
// all-or-nothing — the app validates every row before calling these, and any DB
// error here rolls the whole batch back.

// ImportRow is one CSV row's dry-run outcome shown in the preview.
type ImportRow struct {
	Line   int
	Cells  []string
	Action string // "create", "update", or "error"
	Error  string
}

// ImportResult is the dry-run summary the preview renders, plus the raw CSV text
// carried forward so the confirmed apply re-validates and applies the same file.
type ImportResult struct {
	Type      string
	Columns   []string
	Rows      []ImportRow
	Created   int
	Updated   int
	Errors    int
	FileError string
	CSV       string
}

// AddressExport is one row of the addresses CSV. Subnet is the containing
// subnet's CIDR (informational); import re-locates the subnet from the address.
type AddressExport struct {
	Address  string
	Subnet   string
	State    string
	Hostname string
	Device   string
	Notes    string
}

// SubnetImport is a validated, resolved subnet row ready to upsert by CIDR.
type SubnetImport struct {
	SiteID      string
	CIDR        string
	Name        string
	VLAN        *int
	Description string
}

// AddressImport is a validated, resolved address row ready to upsert by address.
// SubnetID is the located containing subnet; DeviceID is "" when unlinked.
type AddressImport struct {
	Address  string
	SubnetID string
	DeviceID string
	State    string
	Hostname string
	Notes    string
}

// DeviceImport is a validated device row, upserted by name.
type DeviceImport struct {
	Name        string
	Description string
}

func (s *Store) ListAddressesForExport(ctx context.Context) ([]AddressExport, error) {
	rows, err := s.db.Query(ctx, `
SELECT host(ip.address), COALESCE(sub.cidr::text, ''), ip.state::text, ip.hostname, COALESCE(d.name, ''), ip.notes
FROM ip_addresses ip
LEFT JOIN subnets sub ON sub.id = ip.subnet_id
LEFT JOIN devices d ON d.id = ip.device_id
ORDER BY ip.address`)
	if err != nil {
		return nil, fmt.Errorf("list addresses for export: %w", err)
	}
	defer rows.Close()

	var out []AddressExport
	for rows.Next() {
		var a AddressExport
		if err := rows.Scan(&a.Address, &a.Subnet, &a.State, &a.Hostname, &a.Device, &a.Notes); err != nil {
			return nil, fmt.Errorf("scan address export: %w", err)
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// ImportSubnets upserts the given subnets by CIDR in one transaction. The caller
// must have validated each CIDR (IPv4, no overlap) and resolved each site.
func (s *Store) ImportSubnets(ctx context.Context, rows []SubnetImport) error {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin subnet import: %w", err)
	}
	defer tx.Rollback(ctx)

	for _, r := range rows {
		id, err := auth.RandomToken(18)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `
INSERT INTO subnets (id, site_id, cidr, name, vlan, description)
VALUES ($1, $2, $3::cidr, $4, $5, $6)
ON CONFLICT (cidr) DO UPDATE SET
	site_id = EXCLUDED.site_id,
	name = EXCLUDED.name,
	vlan = EXCLUDED.vlan,
	description = EXCLUDED.description,
	updated_at = now()`, id, emptyToNil(r.SiteID), r.CIDR, r.Name, r.VLAN, r.Description); err != nil {
			return fmt.Errorf("import subnet %s: %w", r.CIDR, err)
		}
	}
	return tx.Commit(ctx)
}

// ImportAddresses upserts the given addresses by address in one transaction. The
// caller must have located each containing subnet and resolved each device.
func (s *Store) ImportAddresses(ctx context.Context, rows []AddressImport) error {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin address import: %w", err)
	}
	defer tx.Rollback(ctx)

	for _, r := range rows {
		id, err := auth.RandomToken(18)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `
INSERT INTO ip_addresses (id, subnet_id, device_id, address, state, hostname, notes)
VALUES ($1, $2, $3, $4::inet, $5::address_state, $6, $7)
ON CONFLICT (address) DO UPDATE SET
	subnet_id = EXCLUDED.subnet_id,
	device_id = EXCLUDED.device_id,
	state = EXCLUDED.state,
	hostname = EXCLUDED.hostname,
	notes = EXCLUDED.notes,
	updated_at = now()`, id, emptyToNil(r.SubnetID), emptyToNil(r.DeviceID), r.Address, r.State, r.Hostname, r.Notes); err != nil {
			return fmt.Errorf("import address %s: %w", r.Address, err)
		}
	}
	return tx.Commit(ctx)
}

// ImportDevices upserts the given devices by name in one transaction. Names are
// not unique, so a name that already exists (in the DB or earlier in the same
// batch) updates the first such device; a new name creates one.
func (s *Store) ImportDevices(ctx context.Context, rows []DeviceImport) error {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin device import: %w", err)
	}
	defer tx.Rollback(ctx)

	for _, r := range rows {
		var existingID string
		err := tx.QueryRow(ctx, "SELECT id FROM devices WHERE name = $1 ORDER BY created_at LIMIT 1", r.Name).Scan(&existingID)
		switch {
		case err == nil:
			if _, err := tx.Exec(ctx, "UPDATE devices SET description = $2, updated_at = now() WHERE id = $1", existingID, r.Description); err != nil {
				return fmt.Errorf("import device %s: %w", r.Name, err)
			}
		case err == pgx.ErrNoRows:
			id, err := auth.RandomToken(18)
			if err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, "INSERT INTO devices (id, name, description) VALUES ($1, $2, $3)", id, r.Name, r.Description); err != nil {
				return fmt.Errorf("import device %s: %w", r.Name, err)
			}
		default:
			return fmt.Errorf("lookup device %s: %w", r.Name, err)
		}
	}
	return tx.Commit(ctx)
}
