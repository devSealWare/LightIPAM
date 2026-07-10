package app

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"strings"

	"github.com/devSealWare/LightIPAM/internal/ipam"
	"github.com/devSealWare/LightIPAM/internal/store"
	"github.com/devSealWare/LightIPAM/internal/ui"
)

// CSV import/export (Phase 4.5) — the basic on-ramp distinct from the planned
// Phase 6 NetBox format. Export columns mirror the create/edit forms so an
// export re-imports cleanly. Import validates EVERY row against the same rules
// the forms enforce (IPv4 incl. /31,/32, global subnet-overlap blocking, the
// sparse address model, the address-state enum), shows a dry-run preview with
// per-row errors, and applies only on confirm in a single transaction — an
// invalid file is never partially applied.

// CSV headers, exported and expected on import (matched case-insensitively, by
// name, so column order is flexible).
var (
	subnetCSVColumns  = []string{"name", "cidr", "vlan", "site", "description"}
	addressCSVColumns = []string{"address", "subnet", "state", "hostname", "device", "notes"}
	deviceCSVColumns  = []string{"name", "description"}
)

// The dry-run preview types (importRow/importResult) live in the store package
// so the ui templates can render them without an import cycle; this file aliases
// them for brevity.
type importRow = store.ImportRow
type importResult = store.ImportResult

// existingSubnet is an in-memory copy of a stored subnet used for overlap checks
// and address containment during validation.
type existingSubnet struct {
	prefix netip.Prefix
	cidr   string
}

// importContext is the validated-against state captured once before checking a
// file, so the validators stay pure and unit-testable.
type importContext struct {
	subnets       []existingSubnet
	subnetByCIDR  map[string]string   // normalized cidr -> subnet id
	addresses     map[string]bool     // existing address host strings
	sitesByName   map[string]string   // lower(name) -> site id
	devicesByName map[string][]string // lower(name) -> device ids (slice detects ambiguity)
}

func (ic importContext) containingSubnet(ip string) (string, string, bool) {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return "", "", false
	}
	bestID, bestCIDR, bestBits := "", "", -1
	for _, s := range ic.subnets {
		if s.prefix.Contains(addr) && s.prefix.Bits() > bestBits {
			bestID, bestCIDR, bestBits = ic.subnetByCIDR[s.cidr], s.cidr, s.prefix.Bits()
		}
	}
	return bestID, bestCIDR, bestBits >= 0
}

func (a *App) buildImportContext(r *http.Request) (importContext, error) {
	ic := importContext{
		subnetByCIDR:  map[string]string{},
		addresses:     map[string]bool{},
		sitesByName:   map[string]string{},
		devicesByName: map[string][]string{},
	}
	subnets, err := a.store.ListSubnets(r.Context())
	if err != nil {
		return importContext{}, err
	}
	for _, s := range subnets {
		ic.subnetByCIDR[s.CIDR] = s.ID
		if p, err := netip.ParsePrefix(s.CIDR); err == nil {
			ic.subnets = append(ic.subnets, existingSubnet{prefix: p, cidr: s.CIDR})
		}
	}
	sites, err := a.store.ListSites(r.Context())
	if err != nil {
		return importContext{}, err
	}
	for _, s := range sites {
		ic.sitesByName[strings.ToLower(strings.TrimSpace(s.Name))] = s.ID
	}
	devices, err := a.store.ListDevices(r.Context())
	if err != nil {
		return importContext{}, err
	}
	for _, d := range devices {
		key := strings.ToLower(strings.TrimSpace(d.Name))
		ic.devicesByName[key] = append(ic.devicesByName[key], d.ID)
	}
	addresses, err := a.store.ListAddressesForExport(r.Context())
	if err != nil {
		return importContext{}, err
	}
	for _, addr := range addresses {
		ic.addresses[addr.Address] = true
	}
	return ic, nil
}

// parseCSV reads a CSV body into a lowercased header and its data records.
func parseCSV(body string) ([]string, [][]string, error) {
	reader := csv.NewReader(strings.NewReader(body))
	reader.TrimLeadingSpace = true
	reader.FieldsPerRecord = -1 // tolerate ragged rows; we map by header
	records, err := reader.ReadAll()
	if err != nil {
		return nil, nil, err
	}
	if len(records) == 0 {
		return nil, nil, nil
	}
	header := make([]string, len(records[0]))
	for i, h := range records[0] {
		header[i] = strings.ToLower(strings.TrimSpace(strings.TrimPrefix(h, "\ufeff")))
	}
	return header, records[1:], nil
}

// columnLookup maps required column names to their index, or returns the first
// missing column.
func columnLookup(header, required []string) (map[string]int, string) {
	idx := map[string]int{}
	for i, h := range header {
		idx[h] = i
	}
	for _, name := range required {
		if _, ok := idx[name]; !ok {
			return nil, name
		}
	}
	return idx, ""
}

func cell(row []string, idx map[string]int, name string) string {
	i, ok := idx[name]
	if !ok || i >= len(row) {
		return ""
	}
	return strings.TrimSpace(row[i])
}

func validateSubnets(records [][]string, header []string, ic importContext) (importResult, []store.SubnetImport) {
	res := importResult{Type: "subnets", Columns: subnetCSVColumns}
	idx, missing := columnLookup(header, []string{"name", "cidr"})
	if missing != "" {
		res.FileError = fmt.Sprintf("Missing required column %q.", missing)
		return res, nil
	}

	// Track CIDRs seen in this file to flag in-file duplicates and overlaps.
	type pending struct {
		prefix netip.Prefix
		line   int
	}
	var pendingPrefixes []pending
	seenCIDR := map[string]int{}

	var imports []store.SubnetImport
	for n, row := range records {
		line := n + 2 // 1-based, +1 for header
		out := importRow{Line: line, Cells: row}

		name := cell(row, idx, "name")
		rawCIDR := cell(row, idx, "cidr")
		cidr, err := ipam.NormalizeCIDR(rawCIDR)
		switch {
		case name == "":
			out.Action, out.Error = "error", "Name is required."
		case err != nil:
			out.Action, out.Error = "error", "Enter a valid IPv4 CIDR such as 192.168.10.0/24."
		}
		var vlan *int
		if out.Error == "" {
			vlan, err = store.ParseVLAN(cell(row, idx, "vlan"))
			if err != nil {
				out.Action, out.Error = "error", err.Error()
			}
		}
		siteID := ""
		if out.Error == "" {
			site := cell(row, idx, "site")
			if site != "" {
				id, ok := ic.sitesByName[strings.ToLower(site)]
				if !ok {
					out.Action, out.Error = "error", fmt.Sprintf("Unknown site %q.", site)
				} else {
					siteID = id
				}
			}
		}
		if out.Error == "" {
			if prev, dup := seenCIDR[cidr]; dup {
				out.Action, out.Error = "error", fmt.Sprintf("Duplicate CIDR %s (also on line %d).", cidr, prev)
			}
		}
		var prefix netip.Prefix
		if out.Error == "" {
			prefix, _ = netip.ParsePrefix(cidr)
			// Overlap against other rows in this file (different CIDRs).
			for _, p := range pendingPrefixes {
				if p.prefix.Overlaps(prefix) {
					out.Action, out.Error = "error", fmt.Sprintf("Overlaps the subnet on line %d.", p.line)
					break
				}
			}
		}
		_, isUpdate := ic.subnetByCIDR[cidr]
		if out.Error == "" && !isUpdate {
			// Overlap against existing subnets (an exact CIDR match is an update).
			for _, s := range ic.subnets {
				if s.prefix.Overlaps(prefix) {
					out.Action, out.Error = "error", "Overlaps an existing subnet."
					break
				}
			}
		}

		if out.Error != "" {
			res.Errors++
			res.Rows = append(res.Rows, out)
			continue
		}
		seenCIDR[cidr] = line
		pendingPrefixes = append(pendingPrefixes, pending{prefix: prefix, line: line})
		if isUpdate {
			out.Action = "update"
			res.Updated++
		} else {
			out.Action = "create"
			res.Created++
		}
		res.Rows = append(res.Rows, out)
		imports = append(imports, store.SubnetImport{
			SiteID: siteID, CIDR: cidr, Name: name, VLAN: vlan, Description: cell(row, idx, "description"),
		})
	}
	return res, imports
}

func validateAddresses(records [][]string, header []string, ic importContext) (importResult, []store.AddressImport) {
	res := importResult{Type: "addresses", Columns: addressCSVColumns}
	idx, missing := columnLookup(header, []string{"address", "state"})
	if missing != "" {
		res.FileError = fmt.Sprintf("Missing required column %q.", missing)
		return res, nil
	}

	seen := map[string]int{}
	var imports []store.AddressImport
	for n, row := range records {
		line := n + 2
		out := importRow{Line: line, Cells: row}

		address, err := ipam.NormalizeIPv4(cell(row, idx, "address"))
		state := strings.ToLower(cell(row, idx, "state"))
		var subnetID, deviceID string
		switch {
		case err != nil:
			out.Action, out.Error = "error", "Enter a valid IPv4 address."
		case !validAddressState(state):
			out.Action, out.Error = "error", "State must be available, reserved, assigned, deprecated, or conflict."
		}
		if out.Error == "" {
			if prev, dup := seen[address]; dup {
				out.Action, out.Error = "error", fmt.Sprintf("Duplicate address %s (also on line %d).", address, prev)
			}
		}
		if out.Error == "" {
			id, _, ok := ic.containingSubnet(address)
			if !ok {
				out.Action, out.Error = "error", "No existing subnet contains this address — import its subnet first."
			} else {
				subnetID = id
			}
		}
		if out.Error == "" {
			if device := cell(row, idx, "device"); device != "" {
				ids := ic.devicesByName[strings.ToLower(device)]
				switch len(ids) {
				case 0:
					out.Action, out.Error = "error", fmt.Sprintf("Unknown device %q — import devices first.", device)
				case 1:
					deviceID = ids[0]
				default:
					out.Action, out.Error = "error", fmt.Sprintf("Device name %q is ambiguous (%d devices).", device, len(ids))
				}
			}
		}

		if out.Error != "" {
			res.Errors++
			res.Rows = append(res.Rows, out)
			continue
		}
		seen[address] = line
		if ic.addresses[address] {
			out.Action = "update"
			res.Updated++
		} else {
			out.Action = "create"
			res.Created++
		}
		res.Rows = append(res.Rows, out)
		imports = append(imports, store.AddressImport{
			Address: address, SubnetID: subnetID, DeviceID: deviceID, State: state,
			Hostname: cell(row, idx, "hostname"), Notes: cell(row, idx, "notes"),
		})
	}
	return res, imports
}

func validateDevices(records [][]string, header []string, ic importContext) (importResult, []store.DeviceImport) {
	res := importResult{Type: "devices", Columns: deviceCSVColumns}
	idx, missing := columnLookup(header, []string{"name"})
	if missing != "" {
		res.FileError = fmt.Sprintf("Missing required column %q.", missing)
		return res, nil
	}

	seen := map[string]bool{}
	var imports []store.DeviceImport
	for n, row := range records {
		line := n + 2
		out := importRow{Line: line, Cells: row}

		name := cell(row, idx, "name")
		if name == "" {
			out.Action, out.Error = "error", "Name is required."
			res.Errors++
			res.Rows = append(res.Rows, out)
			continue
		}
		key := strings.ToLower(name)
		_, exists := ic.devicesByName[key]
		if exists || seen[key] {
			out.Action = "update"
			res.Updated++
		} else {
			out.Action = "create"
			res.Created++
		}
		seen[key] = true
		res.Rows = append(res.Rows, out)
		imports = append(imports, store.DeviceImport{Name: name, Description: cell(row, idx, "description")})
	}
	return res, imports
}

func (a *App) importIndex(w http.ResponseWriter, r *http.Request) {
	session, ok := a.requireSession(w, r)
	if !ok {
		return
	}
	_ = ui.Render(w, "import.html", ui.PageData{
		Title:     "Import / Export",
		User:      session.User,
		CSRF:      session.CSRFToken,
		ActiveNav: "import",
	})
}

func (a *App) importPreview(w http.ResponseWriter, r *http.Request) {
	session, ok := a.requireSession(w, r)
	if !ok {
		return
	}
	if !a.verifySessionCSRF(r, session) {
		http.Error(w, "Invalid form token", http.StatusForbidden)
		return
	}
	entity := r.PathValue("type")
	if !validImportType(entity) {
		http.NotFound(w, r)
		return
	}
	if err := r.ParseMultipartForm(8 << 20); err != nil {
		http.Error(w, "Unable to read upload", http.StatusBadRequest)
		return
	}
	file, _, err := r.FormFile("file")
	if err != nil {
		a.renderImportError(w, session, "Choose a CSV file to upload.")
		return
	}
	defer file.Close()
	body, err := io.ReadAll(file)
	if err != nil {
		a.renderImportError(w, session, "Unable to read the uploaded file.")
		return
	}

	result, _ := a.validateImport(r, entity, string(body), normalizeImportFormat(r.FormValue("format")))
	a.renderImportPreview(w, session, result)
}

func (a *App) importApply(w http.ResponseWriter, r *http.Request) {
	session, ok := a.requireSession(w, r)
	if !ok {
		return
	}
	if !a.verifySessionCSRF(r, session) {
		http.Error(w, "Invalid form token", http.StatusForbidden)
		return
	}
	entity := r.PathValue("type")
	if !validImportType(entity) {
		http.NotFound(w, r)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form", http.StatusBadRequest)
		return
	}

	body := r.FormValue("csv")
	result, payload := a.validateImport(r, entity, body, normalizeImportFormat(r.FormValue("format")))
	// Re-validate before applying: never partially apply an invalid file.
	if result.FileError != "" || result.Errors > 0 {
		a.renderImportPreview(w, session, result)
		return
	}

	var err error
	switch entity {
	case "subnets":
		err = a.store.ImportSubnets(r.Context(), payload.([]store.SubnetImport))
	case "addresses":
		err = a.store.ImportAddresses(r.Context(), payload.([]store.AddressImport))
	case "devices":
		err = a.store.ImportDevices(r.Context(), payload.([]store.DeviceImport))
	}
	if err != nil {
		a.logger.Error("import apply", "error", err, "type", entity)
		result.FileError = "The import could not be applied; no changes were made."
		a.renderImportPreview(w, session, result)
		return
	}

	uid := session.User.ID
	actionPrefix, subjectType := importAuditNames(entity)
	metadata, _ := json.Marshal(map[string]any{"created": result.Created, "updated": result.Updated, "format": result.Format})
	if err := a.store.CreateAuditLog(r.Context(), &uid, actionPrefix+".csv_imported", subjectType, "", string(metadata)); err != nil {
		a.logger.Error("create audit log", "error", err)
	}
	http.Redirect(w, r, redirectForImport(entity), http.StatusSeeOther)
}

// validateImport parses and validates a CSV body for the given type and format,
// returning the dry-run result and (when valid) the typed payload for the store
// import. A NetBox-format file is first translated into the canonical Light IPAM
// columns, so the same validators and apply path handle both dialects.
func (a *App) validateImport(r *http.Request, entity, body, format string) (importResult, any) {
	ic, err := a.buildImportContext(r)
	if err != nil {
		a.logger.Error("build import context", "error", err)
		return importResult{Type: entity, Format: format, FileError: "Unable to load current records for validation.", CSV: body}, nil
	}
	header, records, err := parseCSV(body)
	if err != nil {
		return importResult{Type: entity, Format: format, FileError: "The file is not valid CSV.", CSV: body}, nil
	}
	if len(records) == 0 {
		return importResult{Type: entity, Format: format, FileError: "The file has no data rows.", CSV: body}, nil
	}
	if format == formatNetBox {
		canonHeader, canonRecords, fileErr := translateNetBoxImport(entity, header, records)
		if fileErr != "" {
			return importResult{Type: entity, Format: format, FileError: fileErr, CSV: body}, nil
		}
		header, records = canonHeader, canonRecords
	}

	var result importResult
	var payload any
	switch entity {
	case "subnets":
		result, payload = validateSubnets(records, header, ic)
	case "addresses":
		result, payload = validateAddresses(records, header, ic)
	case "devices":
		result, payload = validateDevices(records, header, ic)
	}
	result.CSV = body
	result.Format = format
	return result, payload
}

func (a *App) exportSubnetsCSV(w http.ResponseWriter, r *http.Request) {
	session, ok := a.requireSession(w, r)
	if !ok {
		return
	}
	subnets, err := a.store.ListSubnets(r.Context())
	if err != nil {
		http.Error(w, "Unable to export subnets", http.StatusInternalServerError)
		return
	}
	cw := beginCSV(w, "subnets.csv", subnetCSVColumns)
	for _, s := range subnets {
		vlan := ""
		if s.VLAN != nil {
			vlan = intString(*s.VLAN)
		}
		_ = cw.Write([]string{s.Name, s.CIDR, vlan, s.SiteName, s.Description})
	}
	cw.Flush()
	a.audit(r, &session.User.ID, "subnet.csv_exported", "subnet", "")
}

func (a *App) exportAddressesCSV(w http.ResponseWriter, r *http.Request) {
	session, ok := a.requireSession(w, r)
	if !ok {
		return
	}
	addresses, err := a.store.ListAddressesForExport(r.Context())
	if err != nil {
		http.Error(w, "Unable to export addresses", http.StatusInternalServerError)
		return
	}
	cw := beginCSV(w, "addresses.csv", addressCSVColumns)
	for _, addr := range addresses {
		_ = cw.Write([]string{addr.Address, addr.Subnet, addr.State, addr.Hostname, addr.Device, addr.Notes})
	}
	cw.Flush()
	a.audit(r, &session.User.ID, "address.csv_exported", "ip_address", "")
}

func (a *App) exportDevicesCSV(w http.ResponseWriter, r *http.Request) {
	session, ok := a.requireSession(w, r)
	if !ok {
		return
	}
	devices, err := a.store.ListDevices(r.Context())
	if err != nil {
		http.Error(w, "Unable to export devices", http.StatusInternalServerError)
		return
	}
	cw := beginCSV(w, "devices.csv", deviceCSVColumns)
	for _, d := range devices {
		_ = cw.Write([]string{d.Name, d.Description})
	}
	cw.Flush()
	a.audit(r, &session.User.ID, "device.csv_exported", "device", "")
}

func beginCSV(w http.ResponseWriter, filename string, header []string) *csvCellWriter {
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", "attachment; filename=\""+filename+"\"")
	cw := &csvCellWriter{csv.NewWriter(w)}
	_ = cw.Write(header)
	return cw
}

// csvCellWriter wraps csv.Writer so every exported cell is run through
// sanitizeCSVCell before it reaches the file. encoding/csv only quotes for CSV
// *parsing*; it does not neutralize spreadsheet formulas, so operator- and
// discovery-sourced strings (subnet/device names, DNS/NetBIOS/DHCP hostnames)
// could otherwise execute as formulas when the export is opened in Excel or
// Google Sheets (docs/agent/findings/0001-csv-formula-injection.md).
type csvCellWriter struct {
	w *csv.Writer
}

func (cw *csvCellWriter) Write(record []string) error {
	sanitized := make([]string, len(record))
	for i, v := range record {
		sanitized[i] = sanitizeCSVCell(v)
	}
	return cw.w.Write(sanitized)
}

func (cw *csvCellWriter) Flush() {
	cw.w.Flush()
}

// sanitizeCSVCell prefixes a cell with a leading single quote when it begins
// with a character a spreadsheet application would interpret as a formula
// trigger: =, +, -, @, tab, or carriage return. This is the standard OWASP
// CSV-injection mitigation and preserves the original value (Excel/Sheets
// strip the leading quote on display; other tools see it as a literal string).
func sanitizeCSVCell(s string) string {
	if s == "" {
		return s
	}
	switch s[0] {
	case '=', '+', '-', '@', '\t', '\r':
		return "'" + s
	default:
		return s
	}
}

func (a *App) renderImportPreview(w http.ResponseWriter, session store.Session, result importResult) {
	_ = ui.Render(w, "import_preview.html", ui.PageData{
		Title:        "Import preview",
		User:         session.User,
		CSRF:         session.CSRFToken,
		ActiveNav:    "import",
		ImportResult: result,
	})
}

func (a *App) renderImportError(w http.ResponseWriter, session store.Session, message string) {
	_ = ui.Render(w, "import.html", ui.PageData{
		Title:     "Import / Export",
		Error:     message,
		User:      session.User,
		CSRF:      session.CSRFToken,
		ActiveNav: "import",
	})
}

func validImportType(entity string) bool {
	switch entity {
	case "subnets", "addresses", "devices":
		return true
	}
	return false
}

// importAuditNames maps a plural import type to the audit action prefix and
// subject type used across the app (e.g. "address" actions on "ip_address"),
// keeping CSV import audit consistent with export and bulk-edit entries.
func importAuditNames(entity string) (actionPrefix, subjectType string) {
	switch entity {
	case "subnets":
		return "subnet", "subnet"
	case "addresses":
		return "address", "ip_address"
	case "devices":
		return "device", "device"
	default:
		return entity, entity
	}
}

func redirectForImport(entity string) string {
	switch entity {
	case "addresses":
		return "/subnets"
	case "devices":
		return "/devices"
	default:
		return "/subnets"
	}
}
