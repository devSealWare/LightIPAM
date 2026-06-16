package store

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/devSealWare/LightIPAM/internal/auth"
	"github.com/devSealWare/LightIPAM/internal/ipam"
	"github.com/jackc/pgx/v5"
)

var (
	ErrOverlap          = errors.New("subnet overlaps an existing subnet")
	ErrAddressOutOfCIDR = errors.New("address is outside the subnet")
)

type DashboardStats struct {
	SubnetCount   int
	AddressCount  int
	ConflictCount int
	DeviceCount   int
}

type Site struct {
	ID   string
	Name string
}

type Subnet struct {
	ID             string
	SiteID         string
	SiteName       string
	CIDR           string
	Name           string
	VLAN           *int
	Description    string
	AddressCount   int
	ConflictCount  int
	Capacity       uint64
	UtilizationPct float64
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

type IPAddress struct {
	ID         string
	SubnetID   string
	DeviceID   string
	DeviceName string
	Address    string
	State      string
	Hostname   string
	Notes      string
	// VLAN is the containing subnet's VLAN, populated only where a query joins it
	// (the device page's linked-addresses list). Nil when unset or not loaded.
	VLAN      *int
	CreatedAt time.Time
	UpdatedAt time.Time
}

type SubnetInput struct {
	SiteID      string
	CIDR        string
	Name        string
	VLAN        *int
	Description string
}

type AddressInput struct {
	Address  string
	State    string
	DeviceID string
	Hostname string
	Notes    string
}

func (s *Store) DashboardStats(ctx context.Context) (DashboardStats, error) {
	var stats DashboardStats
	if err := s.db.QueryRow(ctx, `
SELECT
	(SELECT count(*) FROM subnets),
	(SELECT count(*) FROM ip_addresses),
	(SELECT count(*) FROM ip_addresses WHERE state = 'conflict'),
	(SELECT count(*) FROM devices)`).Scan(&stats.SubnetCount, &stats.AddressCount, &stats.ConflictCount, &stats.DeviceCount); err != nil {
		return DashboardStats{}, fmt.Errorf("dashboard stats: %w", err)
	}
	return stats, nil
}

func (s *Store) ListSites(ctx context.Context) ([]Site, error) {
	rows, err := s.db.Query(ctx, "SELECT id, name FROM sites ORDER BY name")
	if err != nil {
		return nil, fmt.Errorf("list sites: %w", err)
	}
	defer rows.Close()

	var sites []Site
	for rows.Next() {
		var site Site
		if err := rows.Scan(&site.ID, &site.Name); err != nil {
			return nil, fmt.Errorf("scan site: %w", err)
		}
		sites = append(sites, site)
	}
	return sites, rows.Err()
}

func (s *Store) ListSubnets(ctx context.Context) ([]Subnet, error) {
	rows, err := s.db.Query(ctx, `
SELECT s.id, COALESCE(s.site_id, ''), COALESCE(si.name, ''), s.cidr::text, s.name, s.vlan, s.description,
	count(ip.id)::int,
	count(ip.id) FILTER (WHERE ip.state = 'conflict')::int,
	s.created_at, s.updated_at
FROM subnets s
LEFT JOIN sites si ON si.id = s.site_id
LEFT JOIN ip_addresses ip ON ip.subnet_id = s.id
GROUP BY s.id, si.name
ORDER BY s.cidr`)
	if err != nil {
		return nil, fmt.Errorf("list subnets: %w", err)
	}
	defer rows.Close()

	var subnets []Subnet
	for rows.Next() {
		subnet, err := scanSubnet(rows)
		if err != nil {
			return nil, err
		}
		subnets = append(subnets, subnet)
	}
	return subnets, rows.Err()
}

func (s *Store) GetSubnet(ctx context.Context, id string) (Subnet, error) {
	var row subnetScanner = s.db.QueryRow(ctx, `
SELECT s.id, COALESCE(s.site_id, ''), COALESCE(si.name, ''), s.cidr::text, s.name, s.vlan, s.description,
	count(ip.id)::int,
	count(ip.id) FILTER (WHERE ip.state = 'conflict')::int,
	s.created_at, s.updated_at
FROM subnets s
LEFT JOIN sites si ON si.id = s.site_id
LEFT JOIN ip_addresses ip ON ip.subnet_id = s.id
WHERE s.id = $1
GROUP BY s.id, si.name`, id)
	subnet, err := scanSubnet(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Subnet{}, ErrNotFound
		}
		return Subnet{}, err
	}
	return subnet, nil
}

func (s *Store) CreateSubnet(ctx context.Context, input SubnetInput) (Subnet, error) {
	if err := s.ensureNoSubnetOverlap(ctx, "", input.CIDR); err != nil {
		return Subnet{}, err
	}
	id, err := auth.RandomToken(18)
	if err != nil {
		return Subnet{}, err
	}
	if _, err := s.db.Exec(ctx, `
INSERT INTO subnets (id, site_id, cidr, name, vlan, description)
VALUES ($1, $2, $3::cidr, $4, $5, $6)`, id, emptyToNil(input.SiteID), input.CIDR, input.Name, input.VLAN, input.Description); err != nil {
		return Subnet{}, fmt.Errorf("create subnet: %w", err)
	}
	return s.GetSubnet(ctx, id)
}

func (s *Store) UpdateSubnet(ctx context.Context, id string, input SubnetInput) (Subnet, error) {
	if err := s.ensureNoSubnetOverlap(ctx, id, input.CIDR); err != nil {
		return Subnet{}, err
	}
	tag, err := s.db.Exec(ctx, `
UPDATE subnets
SET site_id = $2, cidr = $3::cidr, name = $4, vlan = $5, description = $6, updated_at = now()
WHERE id = $1`, id, emptyToNil(input.SiteID), input.CIDR, input.Name, input.VLAN, input.Description)
	if err != nil {
		return Subnet{}, fmt.Errorf("update subnet: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return Subnet{}, ErrNotFound
	}
	return s.GetSubnet(ctx, id)
}

func (s *Store) DeleteSubnet(ctx context.Context, id string) error {
	tag, err := s.db.Exec(ctx, "DELETE FROM subnets WHERE id = $1", id)
	if err != nil {
		return fmt.Errorf("delete subnet: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) ListAddresses(ctx context.Context, subnetID string) ([]IPAddress, error) {
	rows, err := s.db.Query(ctx, `
SELECT ip.id, ip.subnet_id, COALESCE(ip.device_id, ''), COALESCE(d.name, ''), host(ip.address), ip.state::text, ip.hostname, ip.notes, ip.created_at, ip.updated_at
FROM ip_addresses ip
LEFT JOIN devices d ON d.id = ip.device_id
WHERE ip.subnet_id = $1
ORDER BY ip.address`, subnetID)
	if err != nil {
		return nil, fmt.Errorf("list addresses: %w", err)
	}
	defer rows.Close()

	var addresses []IPAddress
	for rows.Next() {
		var address IPAddress
		if err := rows.Scan(&address.ID, &address.SubnetID, &address.DeviceID, &address.DeviceName, &address.Address, &address.State, &address.Hostname, &address.Notes, &address.CreatedAt, &address.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan address: %w", err)
		}
		addresses = append(addresses, address)
	}
	return addresses, rows.Err()
}

func (s *Store) CreateAddress(ctx context.Context, subnet Subnet, input AddressInput) (IPAddress, error) {
	contains, err := ipam.Contains(subnet.CIDR, input.Address)
	if err != nil {
		return IPAddress{}, err
	}
	if !contains {
		return IPAddress{}, ErrAddressOutOfCIDR
	}

	id, err := auth.RandomToken(18)
	if err != nil {
		return IPAddress{}, err
	}
	var address IPAddress
	if err := s.db.QueryRow(ctx, `
INSERT INTO ip_addresses (id, subnet_id, device_id, address, state, hostname, notes)
VALUES ($1, $2, $3, $4::inet, $5::address_state, $6, $7)
RETURNING id, subnet_id, COALESCE(device_id, ''), host(address), state::text, hostname, notes, created_at, updated_at`,
		id, subnet.ID, emptyToNil(input.DeviceID), input.Address, input.State, input.Hostname, input.Notes,
	).Scan(&address.ID, &address.SubnetID, &address.DeviceID, &address.Address, &address.State, &address.Hostname, &address.Notes, &address.CreatedAt, &address.UpdatedAt); err != nil {
		return IPAddress{}, fmt.Errorf("create address: %w", err)
	}
	return address, nil
}

func (s *Store) GetAddress(ctx context.Context, id string) (IPAddress, error) {
	var address IPAddress
	if err := s.db.QueryRow(ctx, `
SELECT ip.id, ip.subnet_id, COALESCE(ip.device_id, ''), COALESCE(d.name, ''), host(ip.address), ip.state::text, ip.hostname, ip.notes, ip.created_at, ip.updated_at
FROM ip_addresses ip
LEFT JOIN devices d ON d.id = ip.device_id
WHERE ip.id = $1`, id).Scan(&address.ID, &address.SubnetID, &address.DeviceID, &address.DeviceName, &address.Address, &address.State, &address.Hostname, &address.Notes, &address.CreatedAt, &address.UpdatedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return IPAddress{}, ErrNotFound
		}
		return IPAddress{}, fmt.Errorf("get address: %w", err)
	}
	return address, nil
}

func (s *Store) UpdateAddress(ctx context.Context, id string, subnet Subnet, input AddressInput) (IPAddress, error) {
	contains, err := ipam.Contains(subnet.CIDR, input.Address)
	if err != nil {
		return IPAddress{}, err
	}
	if !contains {
		return IPAddress{}, ErrAddressOutOfCIDR
	}

	tag, err := s.db.Exec(ctx, `
UPDATE ip_addresses
SET device_id = $2, address = $3::inet, state = $4::address_state, hostname = $5, notes = $6, updated_at = now()
WHERE id = $1`, id, emptyToNil(input.DeviceID), input.Address, input.State, input.Hostname, input.Notes)
	if err != nil {
		return IPAddress{}, fmt.Errorf("update address: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return IPAddress{}, ErrNotFound
	}
	return s.GetAddress(ctx, id)
}

func (s *Store) DeleteAddress(ctx context.Context, id string) error {
	tag, err := s.db.Exec(ctx, "DELETE FROM ip_addresses WHERE id = $1", id)
	if err != nil {
		return fmt.Errorf("delete address: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) ensureNoSubnetOverlap(ctx context.Context, existingID, cidr string) error {
	var overlapID string
	err := s.db.QueryRow(ctx, `
SELECT id
FROM subnets
WHERE cidr && $1::cidr
AND ($2 = '' OR id <> $2)
LIMIT 1`, cidr, existingID).Scan(&overlapID)
	if err == nil {
		return ErrOverlap
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	return fmt.Errorf("check subnet overlap: %w", err)
}

func scanSubnet(scanner subnetScanner) (Subnet, error) {
	var subnet Subnet
	if err := scanner.Scan(
		&subnet.ID,
		&subnet.SiteID,
		&subnet.SiteName,
		&subnet.CIDR,
		&subnet.Name,
		&subnet.VLAN,
		&subnet.Description,
		&subnet.AddressCount,
		&subnet.ConflictCount,
		&subnet.CreatedAt,
		&subnet.UpdatedAt,
	); err != nil {
		return Subnet{}, fmt.Errorf("scan subnet: %w", err)
	}
	capacity, err := ipam.AddressCapacity(subnet.CIDR)
	if err != nil {
		return Subnet{}, err
	}
	subnet.Capacity = capacity
	subnet.UtilizationPct = ipam.UtilizationPercent(uint64(subnet.AddressCount), capacity)
	return subnet, nil
}

type subnetScanner interface {
	Scan(dest ...any) error
}

func ParseVLAN(value string) (*int, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, nil
	}
	vlan, err := strconv.Atoi(value)
	if err != nil || vlan < 1 || vlan > 4094 {
		return nil, fmt.Errorf("VLAN must be between 1 and 4094")
	}
	return &vlan, nil
}

func emptyToNil(value string) any {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	return value
}
