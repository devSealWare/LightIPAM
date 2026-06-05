package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sort"
	"time"

	"github.com/devSealWare/LightIPAM/internal/auth"
	"github.com/devSealWare/LightIPAM/internal/macaddr"
	"github.com/jackc/pgx/v5"
)

type Device struct {
	ID              string
	Name            string
	Description     string
	AddressCount    int
	MACCount        int
	PrivateMACCount int
	Tags            []string
	// Discovery-derived inventory, populated when a device is created or refreshed
	// from a scan import. Empty for manually created devices.
	OSFamily        string
	OSDetail        string
	Services        []DiscoveryService
	DiscoverySource string
	// Primary subnet: the subnet of the device's lowest-numbered IP. Used to
	// group the Devices list. All three are empty for a device with no address.
	PrimarySubnetID   string
	PrimarySubnetName string
	PrimarySubnetCIDR string
	// PrimaryIP is the device's lowest-numbered IP (host form, no prefix),
	// shown in the Devices list. Empty for a device with no address; when
	// AddressCount > 1 the UI adds a "+N" affordance for the remainder.
	PrimaryIP string
	CreatedAt time.Time
	UpdatedAt time.Time
}

// DeviceGroup is a set of devices that share a primary subnet (the subnet of
// each device's lowest IP). Devices with no address fall into a group with an
// empty SubnetID/CIDR, rendered as "Unassigned".
type DeviceGroup struct {
	SubnetID   string
	SubnetName string
	CIDR       string
	Devices    []Device
}

type MACAddress struct {
	ID        string
	DeviceID  string
	Address   string
	Vendor    string
	IsPrivate bool
	CreatedAt time.Time
}

type DeviceInput struct {
	Name        string
	Description string
}

func (s *Store) ListDevices(ctx context.Context) ([]Device, error) {
	rows, err := s.db.Query(ctx, `
SELECT d.id, d.name, d.description,
	count(DISTINCT ip.id)::int,
	count(DISTINCT m.id)::int,
	count(DISTINCT m.id) FILTER (WHERE m.is_private)::int,
	COALESCE(array_remove(array_agg(DISTINCT t.name), NULL), '{}')::text[],
	d.os_family, d.os_detail, d.services::text, d.discovery_source,
	COALESCE(ps.subnet_id, ''), COALESCE(ps.subnet_name, ''), COALESCE(ps.cidr, ''), COALESCE(ps.ip, ''),
	d.created_at, d.updated_at
FROM devices d
LEFT JOIN ip_addresses ip ON ip.device_id = d.id
LEFT JOIN mac_addresses m ON m.device_id = d.id
LEFT JOIN taggings tg ON tg.entity_type = 'device' AND tg.entity_id = d.id
LEFT JOIN tags t ON t.id = tg.tag_id
LEFT JOIN LATERAL (
	SELECT sub.id AS subnet_id, sub.name AS subnet_name, sub.cidr::text AS cidr, host(ipx.address) AS ip
	FROM ip_addresses ipx
	JOIN subnets sub ON sub.id = ipx.subnet_id
	WHERE ipx.device_id = d.id
	ORDER BY ipx.address
	LIMIT 1
) ps ON true
GROUP BY d.id, ps.subnet_id, ps.subnet_name, ps.cidr, ps.ip
ORDER BY d.name`)
	if err != nil {
		return nil, fmt.Errorf("list devices: %w", err)
	}
	defer rows.Close()

	var devices []Device
	for rows.Next() {
		device, err := scanDevice(rows)
		if err != nil {
			return nil, err
		}
		devices = append(devices, device)
	}
	return devices, rows.Err()
}

// ListDeviceGroups returns all devices bucketed by their primary subnet (the
// subnet of each device's lowest IP). Groups are ordered by subnet CIDR, with
// addressless devices collected in a trailing "Unassigned" group (empty
// SubnetID). Within a group, devices keep ListDevices' by-name ordering.
func (s *Store) ListDeviceGroups(ctx context.Context) ([]DeviceGroup, error) {
	devices, err := s.ListDevices(ctx)
	if err != nil {
		return nil, err
	}

	groups := make(map[string]*DeviceGroup)
	for i := range devices {
		d := devices[i]
		g, ok := groups[d.PrimarySubnetID]
		if !ok {
			g = &DeviceGroup{
				SubnetID:   d.PrimarySubnetID,
				SubnetName: d.PrimarySubnetName,
				CIDR:       d.PrimarySubnetCIDR,
			}
			groups[d.PrimarySubnetID] = g
		}
		g.Devices = append(g.Devices, d)
	}

	out := make([]DeviceGroup, 0, len(groups))
	for _, g := range groups {
		out = append(out, *g)
	}
	sort.SliceStable(out, func(i, j int) bool {
		// Unassigned (no subnet) always sorts last.
		if (out[i].SubnetID == "") != (out[j].SubnetID == "") {
			return out[j].SubnetID == ""
		}
		if out[i].CIDR != out[j].CIDR {
			return lessCIDR(out[i].CIDR, out[j].CIDR)
		}
		return out[i].SubnetName < out[j].SubnetName
	})
	return out, nil
}

func (s *Store) GetDevice(ctx context.Context, id string) (Device, error) {
	device, err := scanDevice(s.db.QueryRow(ctx, `
SELECT d.id, d.name, d.description,
	count(DISTINCT ip.id)::int,
	count(DISTINCT m.id)::int,
	count(DISTINCT m.id) FILTER (WHERE m.is_private)::int,
	COALESCE(array_remove(array_agg(DISTINCT t.name), NULL), '{}')::text[],
	d.os_family, d.os_detail, d.services::text, d.discovery_source,
	COALESCE(ps.subnet_id, ''), COALESCE(ps.subnet_name, ''), COALESCE(ps.cidr, ''), COALESCE(ps.ip, ''),
	d.created_at, d.updated_at
FROM devices d
LEFT JOIN ip_addresses ip ON ip.device_id = d.id
LEFT JOIN mac_addresses m ON m.device_id = d.id
LEFT JOIN taggings tg ON tg.entity_type = 'device' AND tg.entity_id = d.id
LEFT JOIN tags t ON t.id = tg.tag_id
LEFT JOIN LATERAL (
	SELECT sub.id AS subnet_id, sub.name AS subnet_name, sub.cidr::text AS cidr, host(ipx.address) AS ip
	FROM ip_addresses ipx
	JOIN subnets sub ON sub.id = ipx.subnet_id
	WHERE ipx.device_id = d.id
	ORDER BY ipx.address
	LIMIT 1
) ps ON true
WHERE d.id = $1
GROUP BY d.id, ps.subnet_id, ps.subnet_name, ps.cidr, ps.ip`, id))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Device{}, ErrNotFound
		}
		return Device{}, err
	}
	return device, nil
}

func (s *Store) CreateDevice(ctx context.Context, input DeviceInput) (Device, error) {
	id, err := auth.RandomToken(18)
	if err != nil {
		return Device{}, err
	}
	if _, err := s.db.Exec(ctx, `
INSERT INTO devices (id, name, description)
VALUES ($1, $2, $3)`, id, input.Name, input.Description); err != nil {
		return Device{}, fmt.Errorf("create device: %w", err)
	}
	return s.GetDevice(ctx, id)
}

func (s *Store) UpdateDevice(ctx context.Context, id string, input DeviceInput) (Device, error) {
	tag, err := s.db.Exec(ctx, `
UPDATE devices
SET name = $2, description = $3, updated_at = now()
WHERE id = $1`, id, input.Name, input.Description)
	if err != nil {
		return Device{}, fmt.Errorf("update device: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return Device{}, ErrNotFound
	}
	return s.GetDevice(ctx, id)
}

func (s *Store) DeleteDevice(ctx context.Context, id string) error {
	tag, err := s.db.Exec(ctx, "DELETE FROM devices WHERE id = $1", id)
	if err != nil {
		return fmt.Errorf("delete device: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) ListMACAddresses(ctx context.Context, deviceID string) ([]MACAddress, error) {
	rows, err := s.db.Query(ctx, `
SELECT id, device_id, address::text, vendor, is_private, created_at
FROM mac_addresses
WHERE device_id = $1
ORDER BY address`, deviceID)
	if err != nil {
		return nil, fmt.Errorf("list mac addresses: %w", err)
	}
	defer rows.Close()

	var addresses []MACAddress
	for rows.Next() {
		var address MACAddress
		if err := rows.Scan(&address.ID, &address.DeviceID, &address.Address, &address.Vendor, &address.IsPrivate, &address.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan mac address: %w", err)
		}
		addresses = append(addresses, address)
	}
	return addresses, rows.Err()
}

func (s *Store) GetMACAddress(ctx context.Context, id string) (MACAddress, error) {
	var address MACAddress
	if err := s.db.QueryRow(ctx, `
SELECT id, device_id, address::text, vendor, is_private, created_at
FROM mac_addresses
WHERE id = $1`, id).Scan(&address.ID, &address.DeviceID, &address.Address, &address.Vendor, &address.IsPrivate, &address.CreatedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return MACAddress{}, ErrNotFound
		}
		return MACAddress{}, fmt.Errorf("get mac address: %w", err)
	}
	return address, nil
}

func (s *Store) ListDeviceIPAddresses(ctx context.Context, deviceID string) ([]IPAddress, error) {
	rows, err := s.db.Query(ctx, `
SELECT ip.id, ip.subnet_id, COALESCE(ip.device_id, ''), COALESCE(d.name, ''), host(ip.address), ip.state::text, ip.hostname, ip.notes, ip.created_at, ip.updated_at
FROM ip_addresses ip
LEFT JOIN devices d ON d.id = ip.device_id
WHERE ip.device_id = $1
ORDER BY ip.address`, deviceID)
	if err != nil {
		return nil, fmt.Errorf("list device addresses: %w", err)
	}
	defer rows.Close()

	var addresses []IPAddress
	for rows.Next() {
		var address IPAddress
		if err := rows.Scan(&address.ID, &address.SubnetID, &address.DeviceID, &address.DeviceName, &address.Address, &address.State, &address.Hostname, &address.Notes, &address.CreatedAt, &address.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan device address: %w", err)
		}
		addresses = append(addresses, address)
	}
	return addresses, rows.Err()
}

func (s *Store) CreateMACAddress(ctx context.Context, deviceID, value string) (MACAddress, error) {
	analysis, err := macaddr.Analyze(value)
	if err != nil {
		return MACAddress{}, err
	}
	id, err := auth.RandomToken(18)
	if err != nil {
		return MACAddress{}, err
	}
	var address MACAddress
	if err := s.db.QueryRow(ctx, `
INSERT INTO mac_addresses (id, device_id, address, vendor, is_private)
VALUES ($1, $2, $3::macaddr, $4, $5)
RETURNING id, device_id, address::text, vendor, is_private, created_at`,
		id, deviceID, analysis.Address, analysis.Vendor, analysis.IsPrivate,
	).Scan(&address.ID, &address.DeviceID, &address.Address, &address.Vendor, &address.IsPrivate, &address.CreatedAt); err != nil {
		return MACAddress{}, fmt.Errorf("create mac address: %w", err)
	}
	if analysis.IsPrivate {
		if err := s.TagDevice(ctx, deviceID, "private-mac", "Private MAC", "amber"); err != nil {
			return MACAddress{}, err
		}
	}
	return address, nil
}

func (s *Store) DeleteMACAddress(ctx context.Context, id string) error {
	tag, err := s.db.Exec(ctx, "DELETE FROM mac_addresses WHERE id = $1", id)
	if err != nil {
		return fmt.Errorf("delete mac address: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) TagDevice(ctx context.Context, deviceID, tagID, name, color string) error {
	if _, err := s.db.Exec(ctx, `
INSERT INTO tags (id, name, color)
VALUES ($1, $2, $3)
ON CONFLICT (id) DO NOTHING`, tagID, name, color); err != nil {
		return fmt.Errorf("ensure tag: %w", err)
	}
	if _, err := s.db.Exec(ctx, `
INSERT INTO taggings (tag_id, entity_type, entity_id)
VALUES ($1, 'device', $2)
ON CONFLICT DO NOTHING`, tagID, deviceID); err != nil {
		return fmt.Errorf("tag device: %w", err)
	}
	return nil
}

// lessCIDR orders two CIDR strings by network address, then prefix length, so
// device-group sections read in natural subnet order. Unparseable values sort
// after parseable ones (and then lexically) rather than panicking.
func lessCIDR(a, b string) bool {
	ipA, netA, errA := net.ParseCIDR(a)
	ipB, netB, errB := net.ParseCIDR(b)
	if errA != nil || errB != nil {
		if errA == nil {
			return true
		}
		if errB == nil {
			return false
		}
		return a < b
	}
	if c := bytes.Compare(ipA.To16(), ipB.To16()); c != 0 {
		return c < 0
	}
	sizeA, _ := netA.Mask.Size()
	sizeB, _ := netB.Mask.Size()
	return sizeA < sizeB
}

func scanDevice(scanner subnetScanner) (Device, error) {
	var device Device
	var servicesJSON string
	if err := scanner.Scan(
		&device.ID,
		&device.Name,
		&device.Description,
		&device.AddressCount,
		&device.MACCount,
		&device.PrivateMACCount,
		&device.Tags,
		&device.OSFamily,
		&device.OSDetail,
		&servicesJSON,
		&device.DiscoverySource,
		&device.PrimarySubnetID,
		&device.PrimarySubnetName,
		&device.PrimarySubnetCIDR,
		&device.PrimaryIP,
		&device.CreatedAt,
		&device.UpdatedAt,
	); err != nil {
		return Device{}, fmt.Errorf("scan device: %w", err)
	}
	if servicesJSON != "" {
		if err := json.Unmarshal([]byte(servicesJSON), &device.Services); err != nil {
			return Device{}, fmt.Errorf("decode device services: %w", err)
		}
	}
	return device, nil
}
