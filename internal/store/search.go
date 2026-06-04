package store

import (
	"context"
	"fmt"
	"strings"
)

// SearchResult is a single hit in a global search, normalized so the UI can
// render every entity type the same way: a primary label, a secondary detail
// line, and a link to the entity's page.
type SearchResult struct {
	Label  string
	Detail string
	URL    string
}

// SearchResults groups global-search hits by entity type.
type SearchResults struct {
	Query     string
	Subnets   []SearchResult
	Addresses []SearchResult
	Devices   []SearchResult
	MACs      []SearchResult
	Total     int
}

// searchLimitPerType caps how many rows each entity category contributes, so a
// broad query (e.g. "192") cannot return an unbounded result set.
const searchLimitPerType = 50

// Search runs a case-insensitive lookup across subnets, IP addresses, devices,
// and MAC addresses. The native inet/cidr/macaddr columns are cast to text so
// ILIKE matching works on the printed form (e.g. "192.168", "aa:bb").
func (s *Store) Search(ctx context.Context, query string) (SearchResults, error) {
	results := SearchResults{Query: query}
	trimmed := strings.TrimSpace(query)
	if trimmed == "" {
		return results, nil
	}
	pattern := "%" + trimmed + "%"

	subnets, err := s.searchSubnets(ctx, pattern)
	if err != nil {
		return SearchResults{}, err
	}
	results.Subnets = subnets

	addresses, err := s.searchAddresses(ctx, pattern)
	if err != nil {
		return SearchResults{}, err
	}
	results.Addresses = addresses

	devices, err := s.searchDevices(ctx, pattern)
	if err != nil {
		return SearchResults{}, err
	}
	results.Devices = devices

	macs, err := s.searchMACs(ctx, pattern)
	if err != nil {
		return SearchResults{}, err
	}
	results.MACs = macs

	results.Total = len(results.Subnets) + len(results.Addresses) + len(results.Devices) + len(results.MACs)
	return results, nil
}

func (s *Store) searchSubnets(ctx context.Context, pattern string) ([]SearchResult, error) {
	rows, err := s.db.Query(ctx, `
SELECT s.id, s.name, s.cidr::text, s.description
FROM subnets s
WHERE s.cidr::text ILIKE $1 OR s.name ILIKE $1 OR s.description ILIKE $1
ORDER BY s.cidr
LIMIT $2`, pattern, searchLimitPerType)
	if err != nil {
		return nil, fmt.Errorf("search subnets: %w", err)
	}
	defer rows.Close()

	var out []SearchResult
	for rows.Next() {
		var id, name, cidr, description string
		if err := rows.Scan(&id, &name, &cidr, &description); err != nil {
			return nil, fmt.Errorf("scan subnet hit: %w", err)
		}
		detail := cidr
		if description != "" {
			detail = cidr + " · " + description
		}
		out = append(out, SearchResult{Label: name, Detail: detail, URL: "/subnets/" + id})
	}
	return out, rows.Err()
}

func (s *Store) searchAddresses(ctx context.Context, pattern string) ([]SearchResult, error) {
	rows, err := s.db.Query(ctx, `
SELECT host(ip.address), ip.subnet_id, COALESCE(ip.hostname, ''), COALESCE(d.name, ''), ip.state::text
FROM ip_addresses ip
LEFT JOIN devices d ON d.id = ip.device_id
WHERE host(ip.address) ILIKE $1 OR ip.hostname ILIKE $1 OR ip.notes ILIKE $1
ORDER BY ip.address
LIMIT $2`, pattern, searchLimitPerType)
	if err != nil {
		return nil, fmt.Errorf("search addresses: %w", err)
	}
	defer rows.Close()

	var out []SearchResult
	for rows.Next() {
		var addr, subnetID, hostname, deviceName, state string
		if err := rows.Scan(&addr, &subnetID, &hostname, &deviceName, &state); err != nil {
			return nil, fmt.Errorf("scan address hit: %w", err)
		}
		parts := []string{state}
		if hostname != "" {
			parts = append(parts, hostname)
		}
		if deviceName != "" {
			parts = append(parts, deviceName)
		}
		out = append(out, SearchResult{
			Label:  addr,
			Detail: strings.Join(parts, " · "),
			URL:    "/subnets/" + subnetID,
		})
	}
	return out, rows.Err()
}

func (s *Store) searchDevices(ctx context.Context, pattern string) ([]SearchResult, error) {
	rows, err := s.db.Query(ctx, `
SELECT d.id, d.name, COALESCE(NULLIF(d.os_detail, ''), NULLIF(d.os_family, '')), d.description
FROM devices d
WHERE d.name ILIKE $1 OR d.description ILIKE $1 OR d.os_detail ILIKE $1 OR d.os_family ILIKE $1
ORDER BY d.name
LIMIT $2`, pattern, searchLimitPerType)
	if err != nil {
		return nil, fmt.Errorf("search devices: %w", err)
	}
	defer rows.Close()

	var out []SearchResult
	for rows.Next() {
		var id, name, osInfo, description string
		if err := rows.Scan(&id, &name, &osInfo, &description); err != nil {
			return nil, fmt.Errorf("scan device hit: %w", err)
		}
		detail := osInfo
		if detail == "" {
			detail = description
		}
		out = append(out, SearchResult{Label: name, Detail: detail, URL: "/devices/" + id})
	}
	return out, rows.Err()
}

func (s *Store) searchMACs(ctx context.Context, pattern string) ([]SearchResult, error) {
	rows, err := s.db.Query(ctx, `
SELECT m.address::text, COALESCE(m.vendor, ''), m.device_id, COALESCE(d.name, '')
FROM mac_addresses m
LEFT JOIN devices d ON d.id = m.device_id
WHERE m.address::text ILIKE $1 OR m.vendor ILIKE $1
ORDER BY m.address
LIMIT $2`, pattern, searchLimitPerType)
	if err != nil {
		return nil, fmt.Errorf("search macs: %w", err)
	}
	defer rows.Close()

	var out []SearchResult
	for rows.Next() {
		var addr, vendor, deviceID, deviceName string
		if err := rows.Scan(&addr, &vendor, &deviceID, &deviceName); err != nil {
			return nil, fmt.Errorf("scan mac hit: %w", err)
		}
		parts := []string{}
		if vendor != "" {
			parts = append(parts, vendor)
		}
		if deviceName != "" {
			parts = append(parts, deviceName)
		}
		out = append(out, SearchResult{
			Label:  addr,
			Detail: strings.Join(parts, " · "),
			URL:    "/devices/" + deviceID,
		})
	}
	return out, rows.Err()
}
