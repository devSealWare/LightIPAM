package store

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/devSealWare/LightIPAM/internal/auth"
	"github.com/jackc/pgx/v5"
)

// LinkedAddress is one of a linked device's IPs with the subnet it lives in,
// for the "Same physical device" card.
type LinkedAddress struct {
	IP         string
	SubnetID   string
	SubnetName string
	SubnetCIDR string
}

// LinkedDevice is a sibling device record in the same hardware group, carrying
// everything the device detail page shows per sibling.
type LinkedDevice struct {
	Device    Device
	Addresses []LinkedAddress
	MACs      []MACAddress
}

// DeviceLinkSuggestion is a candidate device that clears the same-hardware rule
// against the device being viewed. SerialMatch marks a gold-confidence match:
// both devices report the same SNMP chassis serial (ADR 0030), a per-unit
// identifier, rather than only the heuristic hostname + OS-family agreement.
// Suggestions are never applied automatically — the operator confirms or
// dismisses each one (the separate opt-in auto-link acts on serial matches at
// import time, not here).
type DeviceLinkSuggestion struct {
	DeviceID    string
	Name        string
	Hostname    string
	OSFamily    string
	SerialMatch bool
	Addresses   []LinkedAddress
}

// deviceIdentity is the minimal identity the same-hardware rules are decided
// on: the one hostname a device's addresses agree on (empty when absent or
// ambiguous), the discovered OS family, the SNMP chassis serial (ADR 0030),
// and the subnets its IPs live in.
type deviceIdentity struct {
	Hostname  string
	OSFamily  string
	HWSerial  string
	SubnetIDs []string
}

// sameHardwareCandidate reports whether two device records plausibly describe
// the same physical multi-homed device. All of the following must hold:
//
//   - identical, non-empty hostname (trimmed, case-insensitive) — the strong signal;
//   - same non-empty OS family. os_detail is deliberately ignored: interfaces of
//     one box can fingerprint as different releases (a real OPNsense box read
//     "FreeBSD 11.2-RELEASE" on two ports and "FreeBSD 14.3-RELEASE-p15" on the
//     third), so requiring an exact OS string would break the common case;
//   - both devices hold addresses, and their subnet sets are disjoint — a true
//     multi-homed device has at most one IP per subnet, so two devices sharing a
//     subnet are different hosts, never the same hardware.
func sameHardwareCandidate(a, b deviceIdentity) bool {
	hostA, hostB := canonicalIdentity(a.Hostname), canonicalIdentity(b.Hostname)
	if hostA == "" || hostA != hostB {
		return false
	}
	osA, osB := canonicalIdentity(a.OSFamily), canonicalIdentity(b.OSFamily)
	if osA == "" || osA != osB {
		return false
	}
	return disjointSubnets(a.SubnetIDs, b.SubnetIDs)
}

// goldHardwareCandidate reports whether two device records carry the same
// physical-unit identity (ADR 0030): both report the same non-empty SNMP
// chassis serial — compared exactly after trimming, since a serial names one
// unit — and their subnet sets are disjoint and non-empty. The subnet guard is
// kept even at gold confidence: cloned VMs and cheap devices can ship duplicate
// serials, and two records holding addresses in the same subnet are two hosts.
func goldHardwareCandidate(a, b deviceIdentity) bool {
	serialA, serialB := strings.TrimSpace(a.HWSerial), strings.TrimSpace(b.HWSerial)
	if serialA == "" || serialA != serialB {
		return false
	}
	return disjointSubnets(a.SubnetIDs, b.SubnetIDs)
}

// disjointSubnets reports whether both subnet sets are non-empty and share no
// member — the shape of a true multi-homed device (at most one IP per subnet).
func disjointSubnets(a, b []string) bool {
	if len(a) == 0 || len(b) == 0 {
		return false
	}
	seen := make(map[string]bool, len(a))
	for _, id := range a {
		seen[id] = true
	}
	for _, id := range b {
		if seen[id] {
			return false
		}
	}
	return true
}

// canonicalIdentity normalizes an identity signal for comparison: trimmed and
// case-insensitive.
func canonicalIdentity(v string) string {
	return strings.ToLower(strings.TrimSpace(v))
}

// singleHostname reduces a device's distinct address hostnames to its identity
// hostname: the value when exactly one distinct non-empty hostname exists, and
// "" (no identity, so no suggestion) when there is none or the addresses
// disagree.
func singleHostname(hostnames []string) string {
	if len(hostnames) != 1 {
		return ""
	}
	return hostnames[0]
}

// LinkDevices places all given devices into one hardware group: unlinked
// devices join, and any groups already present are merged (every member of a
// touched group is rewritten to the surviving id, so a group is never split).
func (s *Store) LinkDevices(ctx context.Context, ids ...string) error {
	unique := make([]string, 0, len(ids))
	seen := make(map[string]bool, len(ids))
	for _, id := range ids {
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		unique = append(unique, id)
	}
	if len(unique) < 2 {
		return fmt.Errorf("link devices: at least two distinct devices required")
	}

	tx, err := s.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("link devices: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	rows, err := tx.Query(ctx, `
SELECT COALESCE(hardware_group_id, '')
FROM devices
WHERE id = ANY($1)
FOR UPDATE`, unique)
	if err != nil {
		return fmt.Errorf("link devices: %w", err)
	}
	var found int
	var groups []string
	groupSeen := make(map[string]bool)
	for rows.Next() {
		var group string
		if err := rows.Scan(&group); err != nil {
			rows.Close()
			return fmt.Errorf("link devices: %w", err)
		}
		found++
		if group != "" && !groupSeen[group] {
			groupSeen[group] = true
			groups = append(groups, group)
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return fmt.Errorf("link devices: %w", err)
	}
	if found != len(unique) {
		return ErrNotFound
	}

	// Reuse the first existing group id (sorted for determinism) as the
	// surviving group; mint a fresh one only when no device is grouped yet.
	sort.Strings(groups)
	target := ""
	if len(groups) > 0 {
		target = groups[0]
	} else {
		target, err = auth.RandomToken(18)
		if err != nil {
			return err
		}
	}
	if _, err := tx.Exec(ctx, `
UPDATE devices
SET hardware_group_id = $1, updated_at = now()
WHERE id = ANY($2) OR hardware_group_id = ANY($3)`, target, unique, groups); err != nil {
		return fmt.Errorf("link devices: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("link devices: %w", err)
	}
	return nil
}

// UnlinkDevice removes a device from its hardware group. When fewer than two
// members remain the group is dissolved. Unlinking an ungrouped device is a
// no-op.
func (s *Store) UnlinkDevice(ctx context.Context, id string) error {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("unlink device: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var group string
	if err := tx.QueryRow(ctx, `
SELECT COALESCE(hardware_group_id, '')
FROM devices
WHERE id = $1
FOR UPDATE`, id).Scan(&group); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		return fmt.Errorf("unlink device: %w", err)
	}
	if group == "" {
		return nil
	}
	if _, err := tx.Exec(ctx, `
UPDATE devices
SET hardware_group_id = NULL, updated_at = now()
WHERE id = $1`, id); err != nil {
		return fmt.Errorf("unlink device: %w", err)
	}
	if _, err := tx.Exec(ctx, `
UPDATE devices
SET hardware_group_id = NULL, updated_at = now()
WHERE hardware_group_id = $1
	AND (SELECT count(*) FROM devices WHERE hardware_group_id = $1) < 2`, group); err != nil {
		return fmt.Errorf("dissolve device group: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("unlink device: %w", err)
	}
	return nil
}

// ListLinkedDevices returns the other members of a device's hardware group with
// their addresses (and subnets), MACs, OS, and services. Nil when the device is
// not linked.
func (s *Store) ListLinkedDevices(ctx context.Context, deviceID string) ([]LinkedDevice, error) {
	var group string
	if err := s.db.QueryRow(ctx, `
SELECT COALESCE(hardware_group_id, '') FROM devices WHERE id = $1`, deviceID).Scan(&group); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("get device group: %w", err)
	}
	if group == "" {
		return nil, nil
	}

	rows, err := s.db.Query(ctx, `
SELECT id FROM devices WHERE hardware_group_id = $1 AND id <> $2 ORDER BY name, id`, group, deviceID)
	if err != nil {
		return nil, fmt.Errorf("list linked devices: %w", err)
	}
	defer rows.Close()
	var siblingIDs []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("scan linked device: %w", err)
		}
		siblingIDs = append(siblingIDs, id)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	linked := make([]LinkedDevice, 0, len(siblingIDs))
	for _, id := range siblingIDs {
		device, err := s.GetDevice(ctx, id)
		if err != nil {
			return nil, err
		}
		addresses, err := s.listLinkedAddresses(ctx, id)
		if err != nil {
			return nil, err
		}
		macs, err := s.ListMACAddresses(ctx, id)
		if err != nil {
			return nil, err
		}
		linked = append(linked, LinkedDevice{Device: device, Addresses: addresses, MACs: macs})
	}
	return linked, nil
}

// ListDeviceLinkSuggestions returns devices that clear a same-hardware rule
// against the given device, excluding members of its own group and dismissed
// pairs. Two rules feed it: the gold-confidence exact chassis-serial match
// (ADR 0030) and the heuristic hostname + OS-family agreement (ADR 0029). The
// SQL keeps the prefilter cheap (matching serial, or matching hostname + OS
// family; not dismissed, not same group); the pure predicates make the final
// call.
func (s *Store) ListDeviceLinkSuggestions(ctx context.Context, deviceID string) ([]DeviceLinkSuggestion, error) {
	target, group, err := s.deviceLinkIdentity(ctx, deviceID)
	if err != nil {
		return nil, err
	}
	serial := strings.TrimSpace(target.HWSerial)
	heuristic := target.Hostname != "" && target.OSFamily != ""
	if (serial == "" && !heuristic) || len(target.SubnetIDs) == 0 {
		return nil, nil
	}

	rows, err := s.db.Query(ctx, `
SELECT d.id, d.name, d.os_family, btrim(d.hw_serial),
	COALESCE(array_agg(DISTINCT lower(btrim(ip.hostname))) FILTER (WHERE btrim(ip.hostname) <> ''), '{}')::text[],
	COALESCE(array_agg(DISTINCT ip.subnet_id) FILTER (WHERE ip.subnet_id IS NOT NULL), '{}')::text[]
FROM devices d
JOIN ip_addresses ip ON ip.device_id = d.id
WHERE d.id <> $1
	AND (
		($5 <> '' AND btrim(d.hw_serial) = $5)
		OR (
			$4 <> '' AND lower(btrim(d.os_family)) = $2
			AND EXISTS (
				SELECT 1 FROM ip_addresses hn
				WHERE hn.device_id = d.id AND lower(btrim(hn.hostname)) = $4
			)
		)
	)
	AND ($3 = '' OR d.hardware_group_id IS NULL OR d.hardware_group_id <> $3)
	AND NOT EXISTS (
		SELECT 1 FROM device_link_rejections rej
		WHERE rej.device_lo = least(d.id, $1) AND rej.device_hi = greatest(d.id, $1)
	)
GROUP BY d.id
ORDER BY d.name, d.id`,
		deviceID, canonicalIdentity(target.OSFamily), group, canonicalIdentity(target.Hostname), serial)
	if err != nil {
		return nil, fmt.Errorf("list device link suggestions: %w", err)
	}
	defer rows.Close()

	type candidate struct {
		id, name string
		identity deviceIdentity
	}
	var candidates []candidate
	for rows.Next() {
		var c candidate
		var hostnames []string
		if err := rows.Scan(&c.id, &c.name, &c.identity.OSFamily, &c.identity.HWSerial, &hostnames, &c.identity.SubnetIDs); err != nil {
			return nil, fmt.Errorf("scan device link suggestion: %w", err)
		}
		c.identity.Hostname = singleHostname(hostnames)
		candidates = append(candidates, c)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	var suggestions []DeviceLinkSuggestion
	for _, c := range candidates {
		gold := goldHardwareCandidate(target, c.identity)
		if !gold && !sameHardwareCandidate(target, c.identity) {
			continue
		}
		addresses, err := s.listLinkedAddresses(ctx, c.id)
		if err != nil {
			return nil, err
		}
		suggestions = append(suggestions, DeviceLinkSuggestion{
			DeviceID:    c.id,
			Name:        c.name,
			Hostname:    c.identity.Hostname,
			OSFamily:    c.identity.OSFamily,
			SerialMatch: gold,
			Addresses:   addresses,
		})
	}
	return suggestions, nil
}

// AutoLinkDeviceBySerial links a just-imported device to every device carrying
// the same non-empty chassis serial (ADR 0030), when the operator has enabled
// serial auto-linking (the device_link_auto_serial app setting; default off).
// The gold-confidence guards still apply — disjoint subnets, dismissed pairs
// respected — so it never links what an operator declined or what looks like a
// same-subnet serial clone. It returns the ids it linked to (nil when disabled,
// no serial, or no match); callers audit the link.
func (s *Store) AutoLinkDeviceBySerial(ctx context.Context, deviceID string) ([]string, error) {
	var enabled string
	if err := s.db.QueryRow(ctx,
		"SELECT value FROM app_settings WHERE key = $1", SettingDeviceLinkAutoSerial).Scan(&enabled); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("auto-link setting: %w", err)
	}
	if enabled != "true" {
		return nil, nil
	}

	target, group, err := s.deviceLinkIdentity(ctx, deviceID)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil, nil
		}
		return nil, err
	}
	serial := strings.TrimSpace(target.HWSerial)
	if serial == "" || len(target.SubnetIDs) == 0 {
		return nil, nil
	}

	rows, err := s.db.Query(ctx, `
SELECT d.id,
	COALESCE(array_agg(DISTINCT ip.subnet_id) FILTER (WHERE ip.subnet_id IS NOT NULL), '{}')::text[]
FROM devices d
JOIN ip_addresses ip ON ip.device_id = d.id
WHERE d.id <> $1
	AND btrim(d.hw_serial) = $2
	AND ($3 = '' OR d.hardware_group_id IS NULL OR d.hardware_group_id <> $3)
	AND NOT EXISTS (
		SELECT 1 FROM device_link_rejections rej
		WHERE rej.device_lo = least(d.id, $1) AND rej.device_hi = greatest(d.id, $1)
	)
GROUP BY d.id
ORDER BY d.id`, deviceID, serial, group)
	if err != nil {
		return nil, fmt.Errorf("auto-link candidates: %w", err)
	}
	defer rows.Close()

	var matches []string
	for rows.Next() {
		var id string
		var subnetIDs []string
		if err := rows.Scan(&id, &subnetIDs); err != nil {
			return nil, fmt.Errorf("scan auto-link candidate: %w", err)
		}
		if disjointSubnets(target.SubnetIDs, subnetIDs) {
			matches = append(matches, id)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(matches) == 0 {
		return nil, nil
	}

	if err := s.LinkDevices(ctx, append([]string{deviceID}, matches...)...); err != nil {
		return nil, err
	}
	return matches, nil
}

// SettingDeviceLinkAutoSerial is the app_settings key for the opt-in serial
// auto-link (Settings → Discovery). "true" enables it; anything else is off.
const SettingDeviceLinkAutoSerial = "device_link_auto_serial"

// DismissDeviceLinkSuggestion suppresses the unordered device pair from future
// suggestions. Dismissing an already-dismissed pair is a no-op.
func (s *Store) DismissDeviceLinkSuggestion(ctx context.Context, a, b string) error {
	if a == "" || b == "" || a == b {
		return fmt.Errorf("dismiss device link suggestion: two distinct devices required")
	}
	lo, hi := a, b
	if lo > hi {
		lo, hi = hi, lo
	}
	if _, err := s.db.Exec(ctx, `
INSERT INTO device_link_rejections (device_lo, device_hi)
VALUES ($1, $2)
ON CONFLICT DO NOTHING`, lo, hi); err != nil {
		return fmt.Errorf("dismiss device link suggestion: %w", err)
	}
	return nil
}

// deviceLinkIdentity loads the identity the suggestion rule runs on, plus the
// device's current hardware group id (” when unlinked).
func (s *Store) deviceLinkIdentity(ctx context.Context, deviceID string) (deviceIdentity, string, error) {
	var identity deviceIdentity
	var group string
	var hostnames []string
	if err := s.db.QueryRow(ctx, `
SELECT d.os_family, COALESCE(d.hardware_group_id, ''), btrim(d.hw_serial),
	COALESCE(array_agg(DISTINCT lower(btrim(ip.hostname))) FILTER (WHERE btrim(ip.hostname) <> ''), '{}')::text[],
	COALESCE(array_agg(DISTINCT ip.subnet_id) FILTER (WHERE ip.subnet_id IS NOT NULL), '{}')::text[]
FROM devices d
LEFT JOIN ip_addresses ip ON ip.device_id = d.id
WHERE d.id = $1
GROUP BY d.id`, deviceID).Scan(&identity.OSFamily, &group, &identity.HWSerial, &hostnames, &identity.SubnetIDs); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return deviceIdentity{}, "", ErrNotFound
		}
		return deviceIdentity{}, "", fmt.Errorf("get device link identity: %w", err)
	}
	identity.Hostname = singleHostname(hostnames)
	return identity, group, nil
}

// listLinkedAddresses lists a device's IPs with their subnets for the linked
// sibling and suggestion rows. Addresses detached from any subnet are omitted.
func (s *Store) listLinkedAddresses(ctx context.Context, deviceID string) ([]LinkedAddress, error) {
	rows, err := s.db.Query(ctx, `
SELECT host(ip.address), sub.id, sub.name, sub.cidr::text
FROM ip_addresses ip
JOIN subnets sub ON sub.id = ip.subnet_id
WHERE ip.device_id = $1
ORDER BY ip.address`, deviceID)
	if err != nil {
		return nil, fmt.Errorf("list linked addresses: %w", err)
	}
	defer rows.Close()

	var addresses []LinkedAddress
	for rows.Next() {
		var address LinkedAddress
		if err := rows.Scan(&address.IP, &address.SubnetID, &address.SubnetName, &address.SubnetCIDR); err != nil {
			return nil, fmt.Errorf("scan linked address: %w", err)
		}
		addresses = append(addresses, address)
	}
	return addresses, rows.Err()
}
