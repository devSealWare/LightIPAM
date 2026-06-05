package app

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/devSealWare/LightIPAM/internal/scanner"
	"github.com/devSealWare/LightIPAM/internal/store"
	"github.com/devSealWare/LightIPAM/internal/ui"
)

func scanTypeOptions() []string {
	return []string{"host_discovery", "service_detection", "os_probe", "combined", "arp_table", "snmp_inventory"}
}

func scanModeOptions() []string {
	return []string{"passive", "light_active", "standard_active", "deep_active"}
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
	_ = ui.Render(w, "scan_detail.html", ui.PageData{
		Title:            "Scan " + job.ID,
		User:             session.User,
		CSRF:             session.CSRFToken,
		ScanJob:          job,
		ScanObservations: observations,
		ScanErrors:       scanErrors,
		ActiveNav:        "scans",
	})
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
	if !contains(scanModeOptions(), form["mode"]) {
		return store.ScanJobInput{}, errors.New("Select a valid scan mode.")
	}
	allowed := parseList(form["allowed_cidrs"])
	if len(allowed) == 0 {
		return store.ScanJobInput{}, errors.New("Enter at least one allowed IPv4 CIDR.")
	}
	targets := parseList(form["targets"])
	if len(targets) == 0 {
		return store.ScanJobInput{}, errors.New("Enter at least one target.")
	}
	timeout := 60
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
		Mode:           form["mode"],
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
		form = map[string]string{"scan_type": "host_discovery", "mode": "passive", "timeout": "60"}
	}
	_ = ui.Render(w, "scan_new.html", ui.PageData{
		Title:         "Run Scan",
		Error:         message,
		User:          session.User,
		CSRF:          session.CSRFToken,
		ScanAgents:    agents,
		ScanTypes:     scanTypeOptions(),
		ScanModes:     scanModeOptions(),
		DispatchReady: a.scans != nil && a.scans.DispatchEnabled(),
		Form:          form,
		ActiveNav:     "scans",
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
		a.redirectAgents(w, r, "Scanner dispatch is not configured; mount the app's mTLS client certificate first.")
		return
	}
	agent, created, err := a.scans.DiscoverAgent(r.Context(), endpoint)
	if err != nil {
		a.logger.Warn("discover agent", "endpoint", endpoint, "error", err)
		a.redirectAgents(w, r, "Could not reach an agent at that endpoint over mTLS.")
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
	if !contains(scanModeOptions(), form["mode"]) {
		return store.ScanScheduleInput{}, form, errors.New("Select a valid scan mode.")
	}
	allowed := parseList(form["allowed_cidrs"])
	if len(allowed) == 0 {
		return store.ScanScheduleInput{}, form, errors.New("Enter at least one allowed IPv4 CIDR.")
	}
	targets := parseList(form["targets"])
	if len(targets) == 0 {
		return store.ScanScheduleInput{}, form, errors.New("Enter at least one target.")
	}
	interval, err := strconv.Atoi(form["interval"])
	if err != nil || interval < 60 {
		return store.ScanScheduleInput{}, form, errors.New("Interval must be at least 60 seconds.")
	}
	timeout := 60
	if form["timeout"] != "" {
		parsed, err := strconv.Atoi(form["timeout"])
		if err != nil || parsed <= 0 {
			return store.ScanScheduleInput{}, form, errors.New("Timeout must be a positive number of seconds.")
		}
		timeout = parsed
	}
	return store.ScanScheduleInput{
		Name:            form["name"],
		AgentID:         form["agent_id"],
		ScanType:        form["scan_type"],
		Mode:            form["mode"],
		AllowedCIDRs:    allowed,
		Targets:         targets,
		TimeoutSeconds:  timeout,
		IntervalSeconds: interval,
		Enabled:         form["enabled"] == "on" || form["enabled"] == "true",
	}, form, nil
}

func scheduleFormFromSchedule(s store.ScanSchedule) map[string]string {
	enabled := ""
	if s.Enabled {
		enabled = "on"
	}
	return map[string]string{
		"name":          s.Name,
		"agent_id":      s.AgentID,
		"scan_type":     s.ScanType,
		"mode":          s.Mode,
		"allowed_cidrs": strings.Join(s.AllowedCIDRs, "\n"),
		"targets":       strings.Join(s.Targets, "\n"),
		"timeout":       strconv.Itoa(s.TimeoutSeconds),
		"interval":      strconv.Itoa(s.IntervalSeconds),
		"enabled":       enabled,
	}
}

func (a *App) renderScheduleForm(w http.ResponseWriter, r *http.Request, session store.Session, title string, schedule store.ScanSchedule, form map[string]string, message string) {
	agents, err := a.store.ListScanAgents(r.Context())
	if err != nil {
		a.logger.Error("list scan agents", "error", err)
		http.Error(w, "Unable to load form", http.StatusInternalServerError)
		return
	}
	if form == nil {
		form = map[string]string{"scan_type": "host_discovery", "mode": "passive", "timeout": "60", "interval": "3600", "enabled": "on"}
	}
	_ = ui.Render(w, "schedule_form.html", ui.PageData{
		Title:        title,
		Error:        message,
		User:         session.User,
		CSRF:         session.CSRFToken,
		ScanAgents:   agents,
		ScanSchedule: schedule,
		ScanTypes:    scanTypeOptions(),
		ScanModes:    scanModeOptions(),
		Form:         form,
		ActiveNav:    "schedules",
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
