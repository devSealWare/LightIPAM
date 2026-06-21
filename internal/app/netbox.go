package app

import (
	"net/http"
	"net/netip"
	"strings"
)

// NetBox-compatible import/export (Phase 6, ADR 0023). NetBox is a common IPAM/DCIM
// system; this lets an operator move prefixes, IP addresses, and devices between it
// and Light IPAM using NetBox's CSV column names. Import is a pure column/value
// translation into the canonical Light IPAM columns, so it reuses the exact same
// dry-run + all-or-nothing validation pipeline as the native CSV. Export emits
// NetBox's column names with values mapped back.
//
// The object models do not line up perfectly — NetBox prefixes have no "name"
// (only a description) and NetBox devices require role/type/site that Light IPAM
// does not model — so the mapping is intentionally lossy at the documented edges
// (see docs/NETBOX.md). The IPAM core (prefixes ↔ subnets, IP addresses) maps
// cleanly.

const (
	formatLightIPAM = "lightipam"
	formatNetBox    = "netbox"
)

// normalizeImportFormat coerces the submitted format to a known value, defaulting
// to the native Light IPAM CSV.
func normalizeImportFormat(value string) string {
	if strings.ToLower(strings.TrimSpace(value)) == formatNetBox {
		return formatNetBox
	}
	return formatLightIPAM
}

// NetBox export column headers per entity.
var (
	netboxSubnetColumns  = []string{"prefix", "status", "vlan_vid", "site", "description"}
	netboxAddressColumns = []string{"address", "status", "dns_name", "description"}
	netboxDeviceColumns  = []string{"name", "status", "description"}
)

// translateNetBoxImport converts a parsed NetBox CSV (lowercased header + records)
// for the given entity into the canonical Light IPAM columns and rows that the
// existing validators consume. It is pure (no DB) so it is unit-tested directly.
// A missing required NetBox column returns a fileError; row counts and order are
// preserved so the dry-run line numbers still match the uploaded file.
func translateNetBoxImport(entity string, header []string, records [][]string) (canonHeader []string, canonRecords [][]string, fileErr string) {
	idx := map[string]int{}
	for i, h := range header {
		idx[h] = i
	}
	get := func(row []string, name string) string {
		i, ok := idx[name]
		if !ok || i >= len(row) {
			return ""
		}
		return strings.TrimSpace(row[i])
	}
	has := func(name string) bool { _, ok := idx[name]; return ok }

	switch entity {
	case "subnets":
		if !has("prefix") {
			return nil, nil, `NetBox prefix CSV needs a "prefix" column.`
		}
		canonHeader = subnetCSVColumns // name, cidr, vlan, site, description
		for _, row := range records {
			prefix := get(row, "prefix")
			desc := get(row, "description")
			name := desc
			if name == "" {
				name = prefix // NetBox prefixes have no name; fall back to the prefix
			}
			vlan := firstNonEmpty(get(row, "vlan_vid"), get(row, "vlan_id"), get(row, "vlan"))
			canonRecords = append(canonRecords, []string{name, prefix, vlan, get(row, "site"), desc})
		}
	case "addresses":
		if !has("address") {
			return nil, nil, `NetBox IP address CSV needs an "address" column.`
		}
		canonHeader = addressCSVColumns // address, subnet, state, hostname, device, notes
		for _, row := range records {
			canonRecords = append(canonRecords, []string{
				stripMask(get(row, "address")),
				"", // subnet is derived by containment
				mapNetBoxIPStatus(get(row, "status")),
				get(row, "dns_name"),
				"", // NetBox interface assignment is not mapped to a device
				get(row, "description"),
			})
		}
	case "devices":
		if !has("name") {
			return nil, nil, `NetBox device CSV needs a "name" column.`
		}
		canonHeader = deviceCSVColumns // name, description
		for _, row := range records {
			canonRecords = append(canonRecords, []string{
				get(row, "name"),
				firstNonEmpty(get(row, "description"), get(row, "comments")),
			})
		}
	default:
		return nil, nil, "Unsupported import type."
	}
	return canonHeader, canonRecords, ""
}

// mapNetBoxIPStatus maps a NetBox IP-address status to a Light IPAM address state.
// In-use statuses (active/dhcp/slaac and an empty/unknown value) become "assigned".
func mapNetBoxIPStatus(status string) string {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "reserved":
		return "reserved"
	case "deprecated":
		return "deprecated"
	default: // active, dhcp, slaac, empty, or anything unrecognized
		return "assigned"
	}
}

// reverseNetBoxIPStatus maps a Light IPAM address state to the nearest NetBox IP
// status for export. NetBox has no "available"/"conflict", so both fall back to
// "active".
func reverseNetBoxIPStatus(state string) string {
	switch state {
	case "reserved":
		return "reserved"
	case "deprecated":
		return "deprecated"
	default: // assigned, available, conflict
		return "active"
	}
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// stripMask removes a CIDR mask suffix from a NetBox IP address ("10.0.0.5/24" ->
// "10.0.0.5"), leaving the host the Light IPAM model stores.
func stripMask(address string) string {
	if i := strings.IndexByte(address, '/'); i >= 0 {
		return strings.TrimSpace(address[:i])
	}
	return strings.TrimSpace(address)
}

// netboxAddressString renders a Light IPAM host address with the containing
// subnet's mask for NetBox ("10.0.0.5" + "10.0.0.0/24" -> "10.0.0.5/24"), falling
// back to /32 when the subnet is unknown.
func netboxAddressString(address, subnetCIDR string) string {
	if p, err := netip.ParsePrefix(subnetCIDR); err == nil {
		return address + "/" + intString(p.Bits())
	}
	return address + "/32"
}

// --- NetBox exports ---

func (a *App) exportSubnetsNetBox(w http.ResponseWriter, r *http.Request) {
	session, ok := a.requireSession(w, r)
	if !ok {
		return
	}
	subnets, err := a.store.ListSubnets(r.Context())
	if err != nil {
		http.Error(w, "Unable to export subnets", http.StatusInternalServerError)
		return
	}
	cw := beginCSV(w, "prefixes-netbox.csv", netboxSubnetColumns)
	for _, s := range subnets {
		vlan := ""
		if s.VLAN != nil {
			vlan = intString(*s.VLAN)
		}
		// NetBox prefixes carry no name; surface the Light IPAM name as the
		// description so it round-trips back as the subnet name.
		_ = cw.Write([]string{s.CIDR, "active", vlan, s.SiteName, s.Name})
	}
	cw.Flush()
	a.audit(r, &session.User.ID, "subnet.csv_exported", "subnet", "")
}

func (a *App) exportAddressesNetBox(w http.ResponseWriter, r *http.Request) {
	session, ok := a.requireSession(w, r)
	if !ok {
		return
	}
	addresses, err := a.store.ListAddressesForExport(r.Context())
	if err != nil {
		http.Error(w, "Unable to export addresses", http.StatusInternalServerError)
		return
	}
	cw := beginCSV(w, "ip-addresses-netbox.csv", netboxAddressColumns)
	for _, addr := range addresses {
		_ = cw.Write([]string{
			netboxAddressString(addr.Address, addr.Subnet),
			reverseNetBoxIPStatus(addr.State),
			addr.Hostname,
			addr.Notes,
		})
	}
	cw.Flush()
	a.audit(r, &session.User.ID, "address.csv_exported", "ip_address", "")
}

func (a *App) exportDevicesNetBox(w http.ResponseWriter, r *http.Request) {
	session, ok := a.requireSession(w, r)
	if !ok {
		return
	}
	devices, err := a.store.ListDevices(r.Context())
	if err != nil {
		http.Error(w, "Unable to export devices", http.StatusInternalServerError)
		return
	}
	cw := beginCSV(w, "devices-netbox.csv", netboxDeviceColumns)
	for _, d := range devices {
		_ = cw.Write([]string{d.Name, "active", d.Description})
	}
	cw.Flush()
	a.audit(r, &session.User.ID, "device.csv_exported", "device", "")
}
