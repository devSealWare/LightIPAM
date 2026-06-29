package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/devSealWare/LightIPAM/internal/scanner"
	"github.com/devSealWare/LightIPAM/internal/store"
	"github.com/devSealWare/LightIPAM/internal/ui"
)

func scanTypeOptions() []string {
	return []string{"host_discovery", "service_detection", "os_probe", "combined", "arp_table", "snmp_inventory", "name_lookup", "dns_lookup", "dhcp_leases", "lldp_cdp"}
}

// scanTypeGroups arranges the scan types for the form's <optgroup>s so the
// recommended Combined scan leads and the granular options read as advanced. Most
// operators pick Combined and go; the single-source scans are for when you want
// exactly one collection method. Every value here is also in scanTypeOptions (the
// validation set).
func scanTypeGroups() []ui.ScanTypeGroup {
	return []ui.ScanTypeGroup{
		{Label: "Recommended", Types: []string{"combined"}},
		{Label: "Active nmap scans (choose a depth)", Types: []string{"host_discovery", "service_detection", "os_probe"}},
		{Label: "Single-source (advanced)", Types: []string{"arp_table", "snmp_inventory", "name_lookup", "dns_lookup", "dhcp_leases", "lldp_cdp"}},
	}
}

// scanModeOptions lists the user-selectable scan depths for nmap-based scan
// types. The protocol still defines a "passive" mode (the agent's no-packets
// short-circuit), but it produces zero results for every backend, so it is not
// offered as a choice. ARP/SNMP/combined ignore the mode entirely (see
// modeForType) and hide the picker.
func scanModeOptions() []string {
	return []string{"light_active", "standard_active", "deep_active"}
}

// defaultTimeoutForType is the per-host scan timeout (seconds) used when the
// operator leaves the field blank. It scales with how much work the scan type
// does per host and is intentionally generous: a too-low timeout surfaced as
// "context deadline exceeded" on slow or thorough scans (and the app derives its
// dispatch deadline from this per-host budget × the target count). The operator
// can still override it on the form.
func defaultTimeoutForType(scanType string) int {
	switch scanType {
	case "host_discovery":
		return 120
	case "service_detection":
		return 600
	case "os_probe":
		return 900
	case "combined":
		return 1200
	case "arp_table":
		return 180
	case "snmp_inventory":
		return 300
	case "name_lookup":
		return 120
	case "dns_lookup":
		return 120
	case "dhcp_leases":
		return 120
	case "lldp_cdp":
		return 300
	default:
		return 300
	}
}

// modeForType resolves the scan mode to store for a job, given its type. Mode is
// a depth knob that only applies to the plain nmap scan types; ARP and SNMP have
// no depth (a non-passive mode just means "run"), and combined always runs at
// full depth. For those types the submitted mode is ignored and a canonical value
// is substituted, so the form can hide the picker yet still post a valid job even
// with JavaScript disabled.
func modeForType(scanType, mode string) (string, error) {
	switch scanType {
	case "arp_table", "snmp_inventory", "name_lookup", "dns_lookup", "dhcp_leases", "lldp_cdp":
		return "standard_active", nil // SNMP/name/DNS/DHCP lookups have no depth; any active mode runs them
	case "combined":
		return "deep_active", nil // combined always runs deep nmap plus all enrichment passes
	default:
		if !contains(scanModeOptions(), mode) {
			return "", errors.New("Select a valid scan mode.")
		}
		return mode, nil
	}
}

func agentStatusOptions() []string {
	return []string{"pending", "active", "disabled", "revoked"}
}

// parseList splits a textarea/CSV field into trimmed, non-empty entries,
// accepting newline-, comma-, or space-separated input.
func parseList(value string) []string {
	fields := strings.FieldsFunc(value, func(r rune) bool {
		return r == '\n' || r == '\r' || r == ',' || r == ' ' || r == '\t'
	})
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, f)
		}
	}
	return out
}

func contains(values []string, target string) bool {
	for _, v := range values {
		if v == target {
			return true
		}
	}
	return false
}

// validateScanScope enforces, at form-save time, the same address rules the agent
// applies at dispatch (scanner.ValidateJobTargets): every allowed entry must be a
// valid IPv4 CIDR and every target a valid IPv4 address or CIDR contained by the
// allowlist. It exists so an invalid manual scan or schedule is rejected inline
// with a friendly, field-specific message instead of being persisted and then
// silently rejected on every scheduler tick — the cause of the repeated
// scan.schedule.rejected audit entries from a mistyped CIDR like "192.168.5.0.24".
// Pure and unit-tested, mirroring parseScheduleWindow / parseBulkRequest. The
// scanner-level ValidateJobForAgent in enqueue remains the authoritative gate (it
// additionally checks the job allowlist is within the agent's), so these rules are
// kept equivalent by construction (same netip primitives) to avoid drift.
func validateScanScope(allowed, targets []string) error {
	prefixes := make([]netip.Prefix, 0, len(allowed))
	for _, c := range allowed {
		p, err := netip.ParsePrefix(c)
		if err != nil {
			return fmt.Errorf("Allowed CIDR %q is not valid — use a network and prefix length like 192.168.5.0/24.", c)
		}
		if !p.Addr().Is4() {
			return fmt.Errorf("Allowed CIDR %q must be IPv4.", c)
		}
		prefixes = append(prefixes, p.Masked())
	}
	for _, t := range targets {
		if err := validateScanTarget(t, prefixes); err != nil {
			return err
		}
	}
	return nil
}

// validateScanTarget mirrors scanner.validateTarget but returns friendly messages:
// a target is a valid IPv4 address or CIDR and must fall within the allowlist.
func validateScanTarget(target string, allowed []netip.Prefix) error {
	if p, err := netip.ParsePrefix(target); err == nil {
		if !p.Addr().Is4() {
			return fmt.Errorf("Target %q must be IPv4.", target)
		}
		if !prefixWithinAny(p.Masked(), allowed) {
			return fmt.Errorf("Target %q is outside the allowed CIDRs.", target)
		}
		return nil
	}
	addr, err := netip.ParseAddr(target)
	if err != nil {
		return fmt.Errorf("Target %q is not a valid IPv4 address or CIDR — use something like 192.168.5.10 or 192.168.5.0/24.", target)
	}
	if !addr.Is4() {
		return fmt.Errorf("Target %q must be IPv4.", target)
	}
	for _, a := range allowed {
		if a.Contains(addr) {
			return nil
		}
	}
	return fmt.Errorf("Target %q is outside the allowed CIDRs.", target)
}

func prefixWithinAny(target netip.Prefix, allowed []netip.Prefix) bool {
	for _, a := range allowed {
		if a.Contains(target.Addr()) && a.Bits() <= target.Bits() {
			return true
		}
	}
	return false
}

// --- Scan jobs ---

func (a *App) scansIndex(w http.ResponseWriter, r *http.Request) {
	session, ok := a.requireSession(w, r)
	if !ok {
		return
	}
	jobs, err := a.store.ListScanJobs(r.Context(), 50)
	if err != nil {
		a.logger.Error("list scan jobs", "error", err)
		http.Error(w, "Unable to load scans", http.StatusInternalServerError)
		return
	}
	_ = ui.Render(w, "scans.html", ui.PageData{
		Title:         "Scans",
		User:          session.User,
		CSRF:          session.CSRFToken,
		ScanJobs:      jobs,
		DispatchReady: a.scans != nil && a.scans.DispatchEnabled(),
		ActiveNav:     "scans",
	})
}

func (a *App) scanNew(w http.ResponseWriter, r *http.Request) {
	session, ok := a.requireSession(w, r)
	if !ok {
		return
	}
	a.renderScanForm(w, r, session, nil, "")
}

func (a *App) scanCreate(w http.ResponseWriter, r *http.Request) {
	session, ok := a.requireSession(w, r)
	if !ok {
		return
	}
	if !a.verifySessionCSRF(r, session) {
		http.Error(w, "Invalid form token", http.StatusForbidden)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form", http.StatusBadRequest)
		return
	}

	form := map[string]string{
		"agent_id":      strings.TrimSpace(r.FormValue("agent_id")),
		"scan_type":     strings.TrimSpace(r.FormValue("scan_type")),
		"mode":          strings.TrimSpace(r.FormValue("mode")),
		"allowed_cidrs": r.FormValue("allowed_cidrs"),
		"targets":       r.FormValue("targets"),
		"timeout":       strings.TrimSpace(r.FormValue("timeout")),
	}

	input, err := scanInputFromForm(form)
	if err != nil {
		a.renderScanForm(w, r, session, form, err.Error())
		return
	}
	input.RequestedBy = &session.User.ID

	job, err := a.scans.TriggerManual(r.Context(), input)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			a.renderScanForm(w, r, session, form, "Select a registered agent.")
			return
		}
		a.renderScanForm(w, r, session, form, err.Error())
		return
	}
	http.Redirect(w, r, "/scans/"+job.ID, http.StatusSeeOther)
}

func (a *App) scanShow(w http.ResponseWriter, r *http.Request) {
	session, ok := a.requireSession(w, r)
	if !ok {
		return
	}
	job, err := a.store.GetScanJob(r.Context(), r.PathValue("id"))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			http.NotFound(w, r)
			return
		}
		a.logger.Error("get scan job", "error", err)
		http.Error(w, "Unable to load scan", http.StatusInternalServerError)
		return
	}
	observations, scanErrors := parseScanResult(job.Result)
	failures, notices := partitionScanErrors(scanErrors)
	_ = ui.Render(w, "scan_detail.html", ui.PageData{
		Title:            "Scan " + job.ID,
		User:             session.User,
		CSRF:             session.CSRFToken,
		ScanJob:          job,
		ScanObservations: observations,
		ScanErrors:       failures,
		ScanNotices:      notices,
		ActiveNav:        "scans",
	})
}

// partitionScanErrors splits an agent's reported errors into real failures and
// ignored notices (best-effort portions that were skipped, e.g. an SNMP pass
// during a combined scan that got no response). The detail view renders the two
// differently: failures in red, notices as muted "skipped" lines.
func partitionScanErrors(errs []scanner.ScanError) (failures, notices []scanner.ScanError) {
	for _, e := range errs {
		if e.Code == scanner.CodeScanIgnored {
			notices = append(notices, e)
		} else {
			failures = append(failures, e)
		}
	}
	return failures, notices
}

// parseScanResult decodes the agent result JSON stored on a job into structured
// observations and errors for the detail view. A missing or malformed result
// yields nil slices so the template falls back to the raw JSON block.
func parseScanResult(raw string) ([]scanner.Observation, []scanner.ScanError) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	var result scanner.ScanResult
	if err := json.Unmarshal([]byte(raw), &result); err != nil {
		return nil, nil
	}
	return result.Observations, result.Errors
}

func scanInputFromForm(form map[string]string) (store.ScanJobInput, error) {
	if form["agent_id"] == "" {
		return store.ScanJobInput{}, errors.New("Select an agent.")
	}
	if !contains(scanTypeOptions(), form["scan_type"]) {
		return store.ScanJobInput{}, errors.New("Select a valid scan type.")
	}
	mode, err := modeForType(form["scan_type"], form["mode"])
	if err != nil {
		return store.ScanJobInput{}, err
	}
	allowed := parseList(form["allowed_cidrs"])
	if len(allowed) == 0 {
		return store.ScanJobInput{}, errors.New("Enter at least one allowed IPv4 CIDR.")
	}
	targets := parseList(form["targets"])
	if len(targets) == 0 {
		return store.ScanJobInput{}, errors.New("Enter at least one target.")
	}
	if err := validateScanScope(allowed, targets); err != nil {
		return store.ScanJobInput{}, err
	}
	timeout := defaultTimeoutForType(form["scan_type"])
	if form["timeout"] != "" {
		parsed, err := strconv.Atoi(form["timeout"])
		if err != nil || parsed <= 0 {
			return store.ScanJobInput{}, errors.New("Timeout must be a positive number of seconds.")
		}
		timeout = parsed
	}
	return store.ScanJobInput{
		AgentID:        form["agent_id"],
		ScanType:       form["scan_type"],
		Mode:           mode,
		AllowedCIDRs:   allowed,
		Targets:        targets,
		TimeoutSeconds: timeout,
	}, nil
}

func (a *App) renderScanForm(w http.ResponseWriter, r *http.Request, session store.Session, form map[string]string, message string) {
	agents, err := a.store.ListScanAgents(r.Context())
	if err != nil {
		a.logger.Error("list scan agents", "error", err)
		http.Error(w, "Unable to load form", http.StatusInternalServerError)
		return
	}
	if form == nil {
		form = map[string]string{"scan_type": "combined", "mode": "standard_active"}
	}
	_ = ui.Render(w, "scan_new.html", ui.PageData{
		Title:          "Run Scan",
		Error:          message,
		User:           session.User,
		CSRF:           session.CSRFToken,
		ScanAgents:     agents,
		ScanTypes:      scanTypeOptions(),
		ScanTypeGroups: scanTypeGroups(),
		ScanModes:      scanModeOptions(),
		DispatchReady:  a.scans != nil && a.scans.DispatchEnabled(),
		Form:           form,
		ActiveNav:      "scans",
	})
}

// --- Agents ---

func (a *App) agentsIndex(w http.ResponseWriter, r *http.Request) {
	session, ok := a.requireSession(w, r)
	if !ok {
		return
	}
	agents, err := a.store.ListScanAgents(r.Context())
	if err != nil {
		a.logger.Error("list scan agents", "error", err)
		http.Error(w, "Unable to load agents", http.StatusInternalServerError)
		return
	}
	_ = ui.Render(w, "agents.html", ui.PageData{
		Title:         "Scanner Agents",
		User:          session.User,
		CSRF:          session.CSRFToken,
		Error:         r.URL.Query().Get("error"),
		ScanAgents:    agents,
		DispatchReady: a.scans != nil && a.scans.DispatchEnabled(),
		ActiveNav:     "agents",
	})
}

// agentDiscover enrolls an agent by pulling its self-reported identity from the
// endpoint URL the operator supplies. The app connects over mTLS, reads the
// agent's name/allowlist, and creates a pending agent to approve.
func (a *App) agentDiscover(w http.ResponseWriter, r *http.Request) {
	session, ok := a.requireSession(w, r)
	if !ok {
		return
	}
	if !a.verifySessionCSRF(r, session) {
		http.Error(w, "Invalid form token", http.StatusForbidden)
		return
	}
	endpoint := strings.TrimSpace(r.FormValue("endpoint_url"))
	if endpoint == "" || !strings.HasPrefix(endpoint, "https://") {
		a.redirectAgents(w, r, "Enter an https:// endpoint URL to discover an agent.")
		return
	}
	if a.scans == nil {
		a.redirectAgents(w, r, "Scanning isn't set up yet. An administrator needs to install the app's client certificate first.")
		return
	}
	agent, created, err := a.scans.DiscoverAgent(r.Context(), endpoint)
	if err != nil {
		a.logger.Warn("discover agent", "endpoint", endpoint, "error", err)
		a.redirectAgents(w, r, "Couldn't reach an agent at that address. Check the URL and that the agent is running.")
		return
	}
	if created {
		a.audit(r, &session.User.ID, "scan.agent.discovered", "scan_agent", agent.ID)
	}
	http.Redirect(w, r, "/agents", http.StatusSeeOther)
}

// agentApprove transitions a pending agent to active so it can receive jobs.
func (a *App) agentApprove(w http.ResponseWriter, r *http.Request) {
	session, agent, ok := a.loadAgentPage(w, r)
	if !ok {
		return
	}
	if !a.verifySessionCSRF(r, session) {
		http.Error(w, "Invalid form token", http.StatusForbidden)
		return
	}
	if err := a.store.SetScanAgentStatus(r.Context(), agent.ID, "active"); err != nil {
		a.logger.Error("approve agent", "error", err)
		http.Error(w, "Unable to approve agent", http.StatusInternalServerError)
		return
	}
	a.audit(r, &session.User.ID, "scan.agent.approved", "scan_agent", agent.ID)
	http.Redirect(w, r, "/agents", http.StatusSeeOther)
}

func (a *App) redirectAgents(w http.ResponseWriter, r *http.Request, message string) {
	if message == "" {
		http.Redirect(w, r, "/agents", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/agents?error="+url.QueryEscape(message), http.StatusSeeOther)
}

func (a *App) agentNew(w http.ResponseWriter, r *http.Request) {
	session, ok := a.requireSession(w, r)
	if !ok {
		return
	}
	a.renderAgentForm(w, session, "Register Agent", store.ScanAgent{}, nil, "")
}

func (a *App) agentCreate(w http.ResponseWriter, r *http.Request) {
	session, ok := a.requireSession(w, r)
	if !ok {
		return
	}
	if !a.verifySessionCSRF(r, session) {
		http.Error(w, "Invalid form token", http.StatusForbidden)
		return
	}
	input, form, err := agentInputFromRequest(r)
	if err != nil {
		a.renderAgentForm(w, session, "Register Agent", store.ScanAgent{}, form, err.Error())
		return
	}
	agent, err := a.store.CreateScanAgent(r.Context(), input)
	if err != nil {
		a.renderAgentForm(w, session, "Register Agent", store.ScanAgent{}, form, "Unable to register agent.")
		return
	}
	a.audit(r, &session.User.ID, "scan.agent.created", "scan_agent", agent.ID)
	http.Redirect(w, r, "/agents", http.StatusSeeOther)
}

func (a *App) agentEdit(w http.ResponseWriter, r *http.Request) {
	session, agent, ok := a.loadAgentPage(w, r)
	if !ok {
		return
	}
	a.renderAgentForm(w, session, "Edit Agent", agent, agentFormFromAgent(agent), "")
}

func (a *App) agentUpdate(w http.ResponseWriter, r *http.Request) {
	session, agent, ok := a.loadAgentPage(w, r)
	if !ok {
		return
	}
	if !a.verifySessionCSRF(r, session) {
		http.Error(w, "Invalid form token", http.StatusForbidden)
		return
	}
	input, form, err := agentInputFromRequest(r)
	if err != nil {
		a.renderAgentForm(w, session, "Edit Agent", agent, form, err.Error())
		return
	}
	updated, err := a.store.UpdateScanAgent(r.Context(), agent.ID, input)
	if err != nil {
		a.renderAgentForm(w, session, "Edit Agent", agent, form, "Unable to update agent.")
		return
	}
	a.audit(r, &session.User.ID, "scan.agent.updated", "scan_agent", updated.ID)
	http.Redirect(w, r, "/agents", http.StatusSeeOther)
}

func (a *App) agentDeleteConfirm(w http.ResponseWriter, r *http.Request) {
	session, agent, ok := a.loadAgentPage(w, r)
	if !ok {
		return
	}
	_ = ui.Render(w, "confirm.html", ui.PageData{
		Title:     "Delete Agent",
		User:      session.User,
		CSRF:      session.CSRFToken,
		ActiveNav: "agents",
		Form: map[string]string{
			"heading":      "Delete scanner agent",
			"message":      "This removes the agent registration and its schedules. Recorded scan jobs are detached.",
			"subject":      agent.Name,
			"action":       "/agents/" + agent.ID + "/delete",
			"cancel":       "/agents",
			"confirm_text": "Delete agent",
		},
	})
}

func (a *App) agentDelete(w http.ResponseWriter, r *http.Request) {
	session, agent, ok := a.loadAgentPage(w, r)
	if !ok {
		return
	}
	if !a.verifySessionCSRF(r, session) {
		http.Error(w, "Invalid form token", http.StatusForbidden)
		return
	}
	if err := a.store.DeleteScanAgent(r.Context(), agent.ID); err != nil {
		a.logger.Error("delete scan agent", "error", err)
		http.Error(w, "Unable to delete agent", http.StatusInternalServerError)
		return
	}
	a.audit(r, &session.User.ID, "scan.agent.deleted", "scan_agent", agent.ID)
	http.Redirect(w, r, "/agents", http.StatusSeeOther)
}

// agentShow renders the agent detail page — identity, allowlist, status — with a
// "Run diagnostics" control that probes the agent's network self-view on demand.
func (a *App) agentShow(w http.ResponseWriter, r *http.Request) {
	session, agent, ok := a.loadAgentPage(w, r)
	if !ok {
		return
	}
	a.renderAgentDetail(w, session, agent, nil, r.URL.Query().Get("error"))
}

// agentDiagnostics fetches the agent's GET /diagnostics over mTLS and re-renders
// the detail page with the result. On-demand and read-only — nothing is
// persisted, so a refresh simply re-probes. Admin-gated by the authorize
// middleware (an unsafe method).
func (a *App) agentDiagnostics(w http.ResponseWriter, r *http.Request) {
	session, agent, ok := a.loadAgentPage(w, r)
	if !ok {
		return
	}
	if !a.verifySessionCSRF(r, session) {
		http.Error(w, "Invalid form token", http.StatusForbidden)
		return
	}
	if a.scans == nil || !a.scans.DispatchEnabled() {
		a.renderAgentDetail(w, session, agent, nil, "Scanning isn't set up yet, so diagnostics can't be run. An administrator needs to install the app's client certificate first.")
		return
	}
	diag, err := a.scans.AgentDiagnostics(r.Context(), agent.EndpointURL)
	if err != nil {
		a.logger.Warn("agent diagnostics", "agent", agent.ID, "error", err)
		a.renderAgentDetail(w, session, agent, nil, "Couldn't fetch diagnostics: "+err.Error())
		return
	}
	a.renderAgentDetail(w, session, agent, &diag, "")
}

func (a *App) renderAgentDetail(w http.ResponseWriter, session store.Session, agent store.ScanAgent, diag *scanner.AgentDiagnostics, message string) {
	_ = ui.Render(w, "agent_detail.html", ui.PageData{
		Title:            "Agent · " + agent.Name,
		User:             session.User,
		CSRF:             session.CSRFToken,
		Error:            message,
		ScanAgent:        agent,
		AgentDiagnostics: diag,
		DispatchReady:    a.scans != nil && a.scans.DispatchEnabled(),
		ActiveNav:        "agents",
	})
}

func agentInputFromRequest(r *http.Request) (store.ScanAgentInput, map[string]string, error) {
	if err := r.ParseForm(); err != nil {
		return store.ScanAgentInput{}, nil, err
	}
	autoImport := r.FormValue("auto_import") == "on" || r.FormValue("auto_import") == "true"
	form := map[string]string{
		"name":                strings.TrimSpace(r.FormValue("name")),
		"endpoint_url":        strings.TrimSpace(r.FormValue("endpoint_url")),
		"certificate_subject": strings.TrimSpace(r.FormValue("certificate_subject")),
		"allowed_cidrs":       r.FormValue("allowed_cidrs"),
		"status":              strings.TrimSpace(r.FormValue("status")),
	}
	if autoImport {
		form["auto_import"] = "on"
	}
	if form["name"] == "" {
		return store.ScanAgentInput{}, form, errors.New("Agent name is required.")
	}
	if form["endpoint_url"] == "" || !strings.HasPrefix(form["endpoint_url"], "https://") {
		return store.ScanAgentInput{}, form, errors.New("Enter an https:// endpoint URL for the agent.")
	}
	status := form["status"]
	if status == "" {
		status = "pending"
	}
	if !contains(agentStatusOptions(), status) {
		return store.ScanAgentInput{}, form, errors.New("Select a valid status.")
	}
	allowed := parseList(form["allowed_cidrs"])
	if len(allowed) == 0 {
		return store.ScanAgentInput{}, form, errors.New("Enter at least one allowed IPv4 CIDR.")
	}
	return store.ScanAgentInput{
		Name:               form["name"],
		EndpointURL:        form["endpoint_url"],
		CertificateSubject: form["certificate_subject"],
		AllowedCIDRs:       allowed,
		Status:             status,
		AutoImport:         autoImport,
	}, form, nil
}

func agentFormFromAgent(agent store.ScanAgent) map[string]string {
	form := map[string]string{
		"name":                agent.Name,
		"endpoint_url":        agent.EndpointURL,
		"certificate_subject": agent.CertificateSubject,
		"allowed_cidrs":       strings.Join(agent.AllowedCIDRs, "\n"),
		"status":              agent.Status,
	}
	if agent.AutoImport {
		form["auto_import"] = "on"
	}
	return form
}

func (a *App) renderAgentForm(w http.ResponseWriter, session store.Session, title string, agent store.ScanAgent, form map[string]string, message string) {
	if form == nil {
		form = map[string]string{"status": "pending"}
	}
	_ = ui.Render(w, "agent_form.html", ui.PageData{
		Title:         title,
		Error:         message,
		User:          session.User,
		CSRF:          session.CSRFToken,
		ScanAgent:     agent,
		AgentStatuses: agentStatusOptions(),
		Form:          form,
		ActiveNav:     "agents",
	})
}

func (a *App) loadAgentPage(w http.ResponseWriter, r *http.Request) (store.Session, store.ScanAgent, bool) {
	session, ok := a.requireSession(w, r)
	if !ok {
		return store.Session{}, store.ScanAgent{}, false
	}
	agent, err := a.store.GetScanAgent(r.Context(), r.PathValue("id"))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			http.NotFound(w, r)
			return store.Session{}, store.ScanAgent{}, false
		}
		a.logger.Error("get scan agent", "error", err)
		http.Error(w, "Unable to load agent", http.StatusInternalServerError)
		return store.Session{}, store.ScanAgent{}, false
	}
	return session, agent, true
}

// --- Schedules ---

func (a *App) schedulesIndex(w http.ResponseWriter, r *http.Request) {
	session, ok := a.requireSession(w, r)
	if !ok {
		return
	}
	schedules, err := a.store.ListScanSchedules(r.Context())
	if err != nil {
		a.logger.Error("list scan schedules", "error", err)
		http.Error(w, "Unable to load schedules", http.StatusInternalServerError)
		return
	}
	_ = ui.Render(w, "schedules.html", ui.PageData{
		Title:         "Scan Schedules",
		User:          session.User,
		CSRF:          session.CSRFToken,
		ScanSchedules: schedules,
		ActiveNav:     "schedules",
	})
}

func (a *App) scheduleNew(w http.ResponseWriter, r *http.Request) {
	session, ok := a.requireSession(w, r)
	if !ok {
		return
	}
	a.renderScheduleForm(w, r, session, "New Schedule", store.ScanSchedule{}, nil, "")
}

// validateScheduleAgentScope rejects a schedule whose allowed CIDRs are not fully
// contained by the chosen agent's own allowlist, at save time — so the configuration
// can't be persisted and then rejected on every scheduler tick (the failure mode that
// only showed up as repeated scan.schedule.rejected audit entries). Syntax and
// target-within-allowlist are already checked by validateScanScope in
// scheduleInputFromRequest; this adds the job-allowlist ⊆ agent-allowlist check that
// needs the agent loaded. A nil scans service (dispatch disabled) skips the check.
func (a *App) validateScheduleAgentScope(ctx context.Context, input store.ScanScheduleInput) error {
	if a.scans == nil {
		return nil
	}
	err := a.scans.ValidateScope(ctx, store.ScanJobInput{
		AgentID:        input.AgentID,
		ScanType:       input.ScanType,
		Mode:           input.Mode,
		AllowedCIDRs:   input.AllowedCIDRs,
		Targets:        input.Targets,
		TimeoutSeconds: input.TimeoutSeconds,
	})
	if errors.Is(err, store.ErrNotFound) {
		return errors.New("Select a registered agent.")
	}
	return err
}

func (a *App) scheduleCreate(w http.ResponseWriter, r *http.Request) {
	session, ok := a.requireSession(w, r)
	if !ok {
		return
	}
	if !a.verifySessionCSRF(r, session) {
		http.Error(w, "Invalid form token", http.StatusForbidden)
		return
	}
	input, form, err := scheduleInputFromRequest(r)
	if err != nil {
		a.renderScheduleForm(w, r, session, "New Schedule", store.ScanSchedule{}, form, err.Error())
		return
	}
	if err := a.validateScheduleAgentScope(r.Context(), input); err != nil {
		a.renderScheduleForm(w, r, session, "New Schedule", store.ScanSchedule{}, form, err.Error())
		return
	}
	schedule, err := a.store.CreateScanSchedule(r.Context(), input)
	if err != nil {
		a.logger.Error("create scan schedule", "error", err)
		a.renderScheduleForm(w, r, session, "New Schedule", store.ScanSchedule{}, form, "Unable to create schedule.")
		return
	}
	a.audit(r, &session.User.ID, "scan.schedule.created", "scan_schedule", schedule.ID)
	http.Redirect(w, r, "/schedules", http.StatusSeeOther)
}

func (a *App) scheduleEdit(w http.ResponseWriter, r *http.Request) {
	session, schedule, ok := a.loadSchedulePage(w, r)
	if !ok {
		return
	}
	a.renderScheduleForm(w, r, session, "Edit Schedule", schedule, scheduleFormFromSchedule(schedule), "")
}

func (a *App) scheduleUpdate(w http.ResponseWriter, r *http.Request) {
	session, schedule, ok := a.loadSchedulePage(w, r)
	if !ok {
		return
	}
	if !a.verifySessionCSRF(r, session) {
		http.Error(w, "Invalid form token", http.StatusForbidden)
		return
	}
	input, form, err := scheduleInputFromRequest(r)
	if err != nil {
		a.renderScheduleForm(w, r, session, "Edit Schedule", schedule, form, err.Error())
		return
	}
	if err := a.validateScheduleAgentScope(r.Context(), input); err != nil {
		a.renderScheduleForm(w, r, session, "Edit Schedule", schedule, form, err.Error())
		return
	}
	updated, err := a.store.UpdateScanSchedule(r.Context(), schedule.ID, input)
	if err != nil {
		a.renderScheduleForm(w, r, session, "Edit Schedule", schedule, form, "Unable to update schedule.")
		return
	}
	a.audit(r, &session.User.ID, "scan.schedule.updated", "scan_schedule", updated.ID)
	http.Redirect(w, r, "/schedules", http.StatusSeeOther)
}

func (a *App) scheduleRunNow(w http.ResponseWriter, r *http.Request) {
	session, schedule, ok := a.loadSchedulePage(w, r)
	if !ok {
		return
	}
	if !a.verifySessionCSRF(r, session) {
		http.Error(w, "Invalid form token", http.StatusForbidden)
		return
	}
	input := store.ScanJobInput{
		AgentID:        schedule.AgentID,
		ScheduleID:     &schedule.ID,
		RequestedBy:    &session.User.ID,
		ScanType:       schedule.ScanType,
		Mode:           schedule.Mode,
		AllowedCIDRs:   schedule.AllowedCIDRs,
		Targets:        schedule.Targets,
		TimeoutSeconds: schedule.TimeoutSeconds,
	}
	job, err := a.scans.TriggerManual(r.Context(), input)
	if err != nil {
		a.logger.Warn("run schedule now", "schedule_id", schedule.ID, "error", err)
		http.Redirect(w, r, "/schedules", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/scans/"+job.ID, http.StatusSeeOther)
}

func (a *App) scheduleDeleteConfirm(w http.ResponseWriter, r *http.Request) {
	session, schedule, ok := a.loadSchedulePage(w, r)
	if !ok {
		return
	}
	_ = ui.Render(w, "confirm.html", ui.PageData{
		Title:     "Delete Schedule",
		User:      session.User,
		CSRF:      session.CSRFToken,
		ActiveNav: "schedules",
		Form: map[string]string{
			"heading":      "Delete scan schedule",
			"message":      "This removes the recurring scan configuration. Past scan jobs are kept.",
			"subject":      schedule.Name,
			"action":       "/schedules/" + schedule.ID + "/delete",
			"cancel":       "/schedules",
			"confirm_text": "Delete schedule",
		},
	})
}

func (a *App) scheduleDelete(w http.ResponseWriter, r *http.Request) {
	session, schedule, ok := a.loadSchedulePage(w, r)
	if !ok {
		return
	}
	if !a.verifySessionCSRF(r, session) {
		http.Error(w, "Invalid form token", http.StatusForbidden)
		return
	}
	if err := a.store.DeleteScanSchedule(r.Context(), schedule.ID); err != nil {
		a.logger.Error("delete scan schedule", "error", err)
		http.Error(w, "Unable to delete schedule", http.StatusInternalServerError)
		return
	}
	a.audit(r, &session.User.ID, "scan.schedule.deleted", "scan_schedule", schedule.ID)
	http.Redirect(w, r, "/schedules", http.StatusSeeOther)
}

func scheduleInputFromRequest(r *http.Request) (store.ScanScheduleInput, map[string]string, error) {
	if err := r.ParseForm(); err != nil {
		return store.ScanScheduleInput{}, nil, err
	}
	form := map[string]string{
		"name":          strings.TrimSpace(r.FormValue("name")),
		"agent_id":      strings.TrimSpace(r.FormValue("agent_id")),
		"scan_type":     strings.TrimSpace(r.FormValue("scan_type")),
		"mode":          strings.TrimSpace(r.FormValue("mode")),
		"allowed_cidrs": r.FormValue("allowed_cidrs"),
		"targets":       r.FormValue("targets"),
		"timeout":       strings.TrimSpace(r.FormValue("timeout")),
		"interval":      strings.TrimSpace(r.FormValue("interval")),
		"enabled":       strings.TrimSpace(r.FormValue("enabled")),
		"window_start":  strings.TrimSpace(r.FormValue("window_start")),
		"window_end":    strings.TrimSpace(r.FormValue("window_end")),
		"window_tz":     strings.TrimSpace(r.FormValue("window_tz")),
	}
	for _, d := range r.Form["window_day"] {
		if d = strings.TrimSpace(d); d != "" {
			form["window_day_"+d] = "on"
		}
	}
	if form["name"] == "" {
		return store.ScanScheduleInput{}, form, errors.New("Schedule name is required.")
	}
	if form["agent_id"] == "" {
		return store.ScanScheduleInput{}, form, errors.New("Select an agent.")
	}
	if !contains(scanTypeOptions(), form["scan_type"]) {
		return store.ScanScheduleInput{}, form, errors.New("Select a valid scan type.")
	}
	mode, err := modeForType(form["scan_type"], form["mode"])
	if err != nil {
		return store.ScanScheduleInput{}, form, err
	}
	allowed := parseList(form["allowed_cidrs"])
	if len(allowed) == 0 {
		return store.ScanScheduleInput{}, form, errors.New("Enter at least one allowed IPv4 CIDR.")
	}
	targets := parseList(form["targets"])
	if len(targets) == 0 {
		return store.ScanScheduleInput{}, form, errors.New("Enter at least one target.")
	}
	if err := validateScanScope(allowed, targets); err != nil {
		return store.ScanScheduleInput{}, form, err
	}
	interval, err := strconv.Atoi(form["interval"])
	if err != nil || interval < 60 {
		return store.ScanScheduleInput{}, form, errors.New("Interval must be at least 60 seconds.")
	}
	timeout := defaultTimeoutForType(form["scan_type"])
	if form["timeout"] != "" {
		parsed, err := strconv.Atoi(form["timeout"])
		if err != nil || parsed <= 0 {
			return store.ScanScheduleInput{}, form, errors.New("Timeout must be a positive number of seconds.")
		}
		timeout = parsed
	}
	startMin, endMin, days, tz, err := parseScheduleWindow(r.Form)
	if err != nil {
		return store.ScanScheduleInput{}, form, err
	}
	return store.ScanScheduleInput{
		Name:            form["name"],
		AgentID:         form["agent_id"],
		ScanType:        form["scan_type"],
		Mode:            mode,
		AllowedCIDRs:    allowed,
		Targets:         targets,
		TimeoutSeconds:  timeout,
		IntervalSeconds: interval,
		Enabled:         form["enabled"] == "on" || form["enabled"] == "true",
		WindowStartMin:  startMin,
		WindowEndMin:    endMin,
		WindowDays:      days,
		WindowTZ:        tz,
	}, form, nil
}

// parseScheduleWindow validates and normalizes the optional firing-window fields of
// the schedule form. It is pure (no DB and no wall clock beyond a time.LoadLocation
// lookup over the embedded zone database), so it is unit-tested directly, mirroring
// parseBulkRequest / parsePolicySettingsForm. window_start and window_end must be
// supplied together (or both omitted, meaning no time-of-day restriction);
// window_day is a set of weekdays (0=Sunday..6=Saturday); window_tz is an IANA zone
// name (default "UTC").
func parseScheduleWindow(form url.Values) (startMin, endMin *int, days []int, tz string, err error) {
	startRaw := strings.TrimSpace(form.Get("window_start"))
	endRaw := strings.TrimSpace(form.Get("window_end"))
	switch {
	case startRaw == "" && endRaw == "":
		// no time-of-day restriction
	case startRaw == "" || endRaw == "":
		return nil, nil, nil, "", errors.New("Set both a window start and end time, or leave both blank.")
	default:
		sm, e := parseClockMinutes(startRaw)
		if e != nil {
			return nil, nil, nil, "", errors.New("Window start must be a time of day like 01:00.")
		}
		em, e := parseClockMinutes(endRaw)
		if e != nil {
			return nil, nil, nil, "", errors.New("Window end must be a time of day like 05:00.")
		}
		if sm == em {
			return nil, nil, nil, "", errors.New("Window start and end must be different times.")
		}
		startMin, endMin = &sm, &em
	}

	seen := make(map[int]bool, 7)
	for _, raw := range form["window_day"] {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		d, e := strconv.Atoi(raw)
		if e != nil || d < 0 || d > 6 {
			return nil, nil, nil, "", errors.New("Select valid window days.")
		}
		if !seen[d] {
			seen[d] = true
			days = append(days, d)
		}
	}
	sort.Ints(days)

	tz = strings.TrimSpace(form.Get("window_tz"))
	if tz == "" {
		tz = "UTC"
	}
	if tz != "UTC" {
		if _, e := time.LoadLocation(tz); e != nil {
			return nil, nil, nil, "", errors.New("Unknown window timezone; use an IANA name like America/New_York.")
		}
	}
	return startMin, endMin, days, tz, nil
}

// parseClockMinutes parses an "HH:MM" 24-hour time of day into minutes since
// midnight.
func parseClockMinutes(s string) (int, error) {
	parts := strings.SplitN(s, ":", 2)
	if len(parts) != 2 {
		return 0, errors.New("expected HH:MM")
	}
	h, err := strconv.Atoi(strings.TrimSpace(parts[0]))
	if err != nil || h < 0 || h > 23 {
		return 0, errors.New("hour out of range")
	}
	m, err := strconv.Atoi(strings.TrimSpace(parts[1]))
	if err != nil || m < 0 || m > 59 {
		return 0, errors.New("minute out of range")
	}
	return h*60 + m, nil
}

func scheduleFormFromSchedule(s store.ScanSchedule) map[string]string {
	enabled := ""
	if s.Enabled {
		enabled = "on"
	}
	tz := s.WindowTZ
	if tz == "" {
		tz = "UTC"
	}
	form := map[string]string{
		"name":          s.Name,
		"agent_id":      s.AgentID,
		"scan_type":     s.ScanType,
		"mode":          s.Mode,
		"allowed_cidrs": strings.Join(s.AllowedCIDRs, "\n"),
		"targets":       strings.Join(s.Targets, "\n"),
		"timeout":       strconv.Itoa(s.TimeoutSeconds),
		"interval":      strconv.Itoa(s.IntervalSeconds),
		"enabled":       enabled,
		"window_tz":     tz,
	}
	if s.WindowStartMin != nil {
		form["window_start"] = clockFromMinutes(*s.WindowStartMin)
	}
	if s.WindowEndMin != nil {
		form["window_end"] = clockFromMinutes(*s.WindowEndMin)
	}
	for _, d := range s.WindowDays {
		if d >= 0 && d <= 6 {
			form["window_day_"+strconv.Itoa(d)] = "on"
		}
	}
	return form
}

// clockFromMinutes renders minutes-since-midnight as an "HH:MM" value for the
// schedule form's time inputs.
func clockFromMinutes(m int) string {
	return fmt.Sprintf("%02d:%02d", m/60, m%60)
}

func (a *App) renderScheduleForm(w http.ResponseWriter, r *http.Request, session store.Session, title string, schedule store.ScanSchedule, form map[string]string, message string) {
	agents, err := a.store.ListScanAgents(r.Context())
	if err != nil {
		a.logger.Error("list scan agents", "error", err)
		http.Error(w, "Unable to load form", http.StatusInternalServerError)
		return
	}
	if form == nil {
		form = map[string]string{"scan_type": "combined", "mode": "standard_active", "interval": "3600", "enabled": "on", "window_tz": "UTC"}
	}
	_ = ui.Render(w, "schedule_form.html", ui.PageData{
		Title:          title,
		Error:          message,
		User:           session.User,
		CSRF:           session.CSRFToken,
		ScanAgents:     agents,
		ScanSchedule:   schedule,
		ScanTypes:      scanTypeOptions(),
		ScanTypeGroups: scanTypeGroups(),
		ScanModes:      scanModeOptions(),
		Form:           form,
		ActiveNav:      "schedules",
	})
}

func (a *App) loadSchedulePage(w http.ResponseWriter, r *http.Request) (store.Session, store.ScanSchedule, bool) {
	session, ok := a.requireSession(w, r)
	if !ok {
		return store.Session{}, store.ScanSchedule{}, false
	}
	schedule, err := a.store.GetScanSchedule(r.Context(), r.PathValue("id"))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			http.NotFound(w, r)
			return store.Session{}, store.ScanSchedule{}, false
		}
		a.logger.Error("get scan schedule", "error", err)
		http.Error(w, "Unable to load schedule", http.StatusInternalServerError)
		return store.Session{}, store.ScanSchedule{}, false
	}
	return session, schedule, true
}
