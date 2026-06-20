package app

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/devSealWare/LightIPAM/internal/store"
	"github.com/devSealWare/LightIPAM/internal/ui"
)

// Stable check ids. They double as the audit/event vocabulary and the group keys
// on the /policy page.
const (
	checkOverlappingSubnets = "overlapping_subnets"
	checkStaleRecords       = "stale_records"
	checkUnmanagedServices  = "unmanaged_services"
)

// PolicySettings is the runtime-tunable policy/health configuration: which checks
// run and the stale-record threshold. Boot defaults come from env (config); an
// admin overrides them from the Settings → Policy tab, which persists them in
// app_settings. The app keeps the active values cached (settingsMu).
type PolicySettings struct {
	CheckOverlaps         bool
	CheckStale            bool
	CheckServices         bool
	StaleAfter            time.Duration
	StaleIncludeNeverSeen bool
}

// app_settings keys for the persisted policy configuration.
const (
	settingPolicyCheckOverlaps  = "policy_check_overlaps"
	settingPolicyCheckStale     = "policy_check_stale"
	settingPolicyCheckServices  = "policy_check_services"
	settingPolicyStaleAfter     = "policy_stale_after"
	settingPolicyStaleNeverSeen = "policy_stale_include_never_seen"
)

func (a *App) defaultPolicySettings() PolicySettings {
	return PolicySettings{
		CheckOverlaps:         true,
		CheckStale:            true,
		CheckServices:         true,
		StaleAfter:            a.cfg.PolicyStaleAfter,
		StaleIncludeNeverSeen: false,
	}
}

// mergePolicySettings overlays any DB-stored policy settings onto the env
// defaults. A missing/invalid value falls back to its default, so a partially
// populated table never disables a check unintentionally or sets a zero
// threshold.
func (a *App) mergePolicySettings(stored map[string]string) PolicySettings {
	s := a.defaultPolicySettings()
	if v, ok := stored[settingPolicyCheckOverlaps]; ok {
		s.CheckOverlaps = v == "true"
	}
	if v, ok := stored[settingPolicyCheckStale]; ok {
		s.CheckStale = v == "true"
	}
	if v, ok := stored[settingPolicyCheckServices]; ok {
		s.CheckServices = v == "true"
	}
	if d, err := time.ParseDuration(stored[settingPolicyStaleAfter]); err == nil && d > 0 {
		s.StaleAfter = d
	}
	if v, ok := stored[settingPolicyStaleNeverSeen]; ok {
		s.StaleIncludeNeverSeen = v == "true"
	}
	return s
}

func (a *App) policySettings() PolicySettings {
	a.settingsMu.RLock()
	defer a.settingsMu.RUnlock()
	return a.policy
}

func (a *App) setPolicySettings(s PolicySettings) {
	a.settingsMu.Lock()
	defer a.settingsMu.Unlock()
	a.policy = s
}

// toMap serializes the settings for app_settings (canonical Go-duration string
// for the threshold, "true"/"false" for the toggles).
func (s PolicySettings) toMap() map[string]string {
	return map[string]string{
		settingPolicyCheckOverlaps:  strconv.FormatBool(s.CheckOverlaps),
		settingPolicyCheckStale:     strconv.FormatBool(s.CheckStale),
		settingPolicyCheckServices:  strconv.FormatBool(s.CheckServices),
		settingPolicyStaleAfter:     s.StaleAfter.String(),
		settingPolicyStaleNeverSeen: strconv.FormatBool(s.StaleIncludeNeverSeen),
	}
}

// formValues renders the settings as the Form map the Policy tab pre-fills, with
// the threshold expressed in days.
func (s PolicySettings) formValues() map[string]string {
	form := map[string]string{
		"policy_stale_days": strconv.Itoa(durationDays(s.StaleAfter)),
	}
	if s.CheckOverlaps {
		form["policy_check_overlaps"] = "on"
	}
	if s.CheckStale {
		form["policy_check_stale"] = "on"
	}
	if s.CheckServices {
		form["policy_check_services"] = "on"
	}
	if s.StaleIncludeNeverSeen {
		form["policy_stale_never_seen"] = "on"
	}
	return form
}

// submittedPolicyForm echoes the raw submitted values back so an invalid
// submission re-renders with what the operator entered.
func submittedPolicyForm(form url.Values) map[string]string {
	out := map[string]string{
		"policy_stale_days": form.Get("policy_stale_days"),
	}
	for _, key := range []string{"policy_check_overlaps", "policy_check_stale", "policy_check_services", "policy_stale_never_seen"} {
		if form.Get(key) != "" {
			out[key] = "on"
		}
	}
	return out
}

// parsePolicySettingsForm validates and converts the Policy-tab form into a
// PolicySettings. Pure so it is unit-tested without a request or DB.
func parsePolicySettingsForm(form url.Values) (PolicySettings, error) {
	days, err := intInRange(form.Get("policy_stale_days"), 1, 3650)
	if err != nil {
		return PolicySettings{}, errors.New("Stale threshold must be a whole number of days between 1 and 3650.")
	}
	return PolicySettings{
		CheckOverlaps:         form.Get("policy_check_overlaps") != "",
		CheckStale:            form.Get("policy_check_stale") != "",
		CheckServices:         form.Get("policy_check_services") != "",
		StaleAfter:            time.Duration(days) * 24 * time.Hour,
		StaleIncludeNeverSeen: form.Get("policy_stale_never_seen") != "",
	}, nil
}

func durationDays(d time.Duration) int {
	if days := int(d / (24 * time.Hour)); days >= 1 {
		return days
	}
	return 1
}

// evaluateOverlaps flags pairs of subnets whose CIDRs cover overlapping address
// space. Pure: it takes the subnet snapshot and returns findings. Note the
// create and CSV-import paths already reject an overlapping subnet, so in normal
// operation this finds nothing — it is an invariant check that catches space
// introduced out of band (a restored older dump, a direct DB edit).
func evaluateOverlaps(subnets []store.PolicySubnet) []store.PolicyFinding {
	type parsed struct {
		sn  store.PolicySubnet
		net *net.IPNet
	}
	var ps []parsed
	for _, sn := range subnets {
		_, ipnet, err := net.ParseCIDR(sn.CIDR)
		if err != nil || ipnet == nil {
			continue
		}
		ps = append(ps, parsed{sn, ipnet})
	}
	var findings []store.PolicyFinding
	for i := 0; i < len(ps); i++ {
		for j := i + 1; j < len(ps); j++ {
			if !cidrsOverlap(ps[i].net, ps[j].net) {
				continue
			}
			a, b := ps[i].sn, ps[j].sn
			findings = append(findings, store.PolicyFinding{
				Check:    checkOverlappingSubnets,
				Severity: store.SeverityCritical,
				Title:    fmt.Sprintf("%s overlaps %s", a.CIDR, b.CIDR),
				Detail:   fmt.Sprintf("%q (%s) and %q (%s) cover overlapping address space, so ownership of the shared addresses is ambiguous.", a.Name, a.CIDR, b.Name, b.CIDR),
				Link:     "/subnets/" + a.ID,
			})
		}
	}
	return findings
}

// cidrsOverlap reports whether two aligned CIDR blocks share any address. For
// prefix-aligned networks, one network's address being inside the other is
// equivalent to the ranges overlapping.
func cidrsOverlap(a, b *net.IPNet) bool {
	return a.Contains(b.IP) || b.Contains(a.IP)
}

// evaluateStaleRecords flags managed records not seen recently. A record older
// than the threshold is a warning; a never-seen record is a lower-severity info
// finding, and only when the operator opts in (off by default so a manual-only
// deployment that never scans is not flooded). Pure over the record snapshot.
func evaluateStaleRecords(records []store.PolicyRecord, settings PolicySettings, now time.Time) []store.PolicyFinding {
	cutoff := now.Add(-settings.StaleAfter)
	var findings []store.PolicyFinding
	for _, rec := range records {
		switch {
		case rec.LastSeen == nil:
			if !settings.StaleIncludeNeverSeen {
				continue
			}
			findings = append(findings, store.PolicyFinding{
				Check:    checkStaleRecords,
				Severity: store.SeverityInfo,
				Title:    staleTitle(rec, "has never been seen by a scan"),
				Detail:   staleDetail(rec, "has no recorded discovery sighting"),
				Link:     rec.Link,
			})
		case rec.LastSeen.Before(cutoff):
			seen := rec.LastSeen.Format("2006-01-02")
			findings = append(findings, store.PolicyFinding{
				Check:    checkStaleRecords,
				Severity: store.SeverityWarning,
				Title:    staleTitle(rec, "last seen "+seen),
				Detail:   staleDetail(rec, "has not been seen since "+seen),
				Link:     rec.Link,
			})
		}
	}
	return findings
}

func staleTitle(rec store.PolicyRecord, phrase string) string {
	if rec.Kind == "device" {
		return fmt.Sprintf("Device %s %s", rec.Label, phrase)
	}
	return fmt.Sprintf("Address %s %s", rec.Label, phrase)
}

func staleDetail(rec store.PolicyRecord, phrase string) string {
	if rec.Kind == "device" {
		return fmt.Sprintf("Device %q %s. It may have been retired.", rec.Label, phrase)
	}
	context := ""
	if rec.Context != "" {
		context = " in " + rec.Context
	}
	return fmt.Sprintf("Address %s%s (%s) %s. It may be safe to release.", rec.Label, context, rec.State, phrase)
}

// evaluateUnmanagedServices flags pending discoveries: a conflict with a managed
// record is critical (reusing the stored reconcile note), and a not-yet-imported
// host running services is a warning. Pure over the discovery snapshot.
func evaluateUnmanagedServices(discoveries []store.PolicyDiscoveryRecord) []store.PolicyFinding {
	var findings []store.PolicyFinding
	for _, d := range discoveries {
		switch d.ReconcileStatus {
		case store.ReconcileConflict:
			detail := d.Conflict
			if detail == "" {
				detail = "The observation disagrees with a managed record."
			}
			findings = append(findings, store.PolicyFinding{
				Check:    checkUnmanagedServices,
				Severity: store.SeverityCritical,
				Title:    "Conflict on " + discoveryLabel(d),
				Detail:   detail + " Resolve it in the review queue.",
				Link:     d.Link,
			})
		case store.ReconcileNew:
			if d.ServiceCount <= 0 {
				continue
			}
			findings = append(findings, store.PolicyFinding{
				Check:    checkUnmanagedServices,
				Severity: store.SeverityWarning,
				Title:    fmt.Sprintf("Unmanaged host %s with %d open service(s)", discoveryLabel(d), d.ServiceCount),
				Detail:   "This host is running services but is not in IPAM. Import or dismiss it in the review queue.",
				Link:     d.Link,
			})
		}
	}
	return findings
}

func discoveryLabel(d store.PolicyDiscoveryRecord) string {
	if d.Hostname != "" {
		return d.Hostname + " (" + d.IP + ")"
	}
	return d.IP
}

// summarizeFindings counts findings by severity for the widget and header. Pure.
func summarizeFindings(findings []store.PolicyFinding) store.PolicySummary {
	var s store.PolicySummary
	for _, f := range findings {
		switch f.Severity {
		case store.SeverityCritical:
			s.Critical++
		case store.SeverityWarning:
			s.Warning++
		case store.SeverityInfo:
			s.Info++
		}
	}
	return s
}

// computePolicy runs the enabled checks against fresh snapshots and returns the
// grouped findings plus a severity summary. Each check fetches only the data it
// needs, so a disabled check costs nothing. Shared by the /policy page and the
// dashboard widget.
func (a *App) computePolicy(ctx context.Context) ([]store.PolicyFindingGroup, store.PolicySummary, error) {
	settings := a.policySettings()
	var (
		groups []store.PolicyFindingGroup
		all    []store.PolicyFinding
	)

	if settings.CheckOverlaps {
		subnets, err := a.store.PolicySubnets(ctx)
		if err != nil {
			return nil, store.PolicySummary{}, err
		}
		f := evaluateOverlaps(subnets)
		groups = append(groups, store.PolicyFindingGroup{Check: checkOverlappingSubnets, Label: "Overlapping subnets", Findings: f})
		all = append(all, f...)
	}

	if settings.CheckStale {
		addresses, err := a.store.PolicyAddressRecords(ctx)
		if err != nil {
			return nil, store.PolicySummary{}, err
		}
		devices, err := a.store.PolicyDeviceRecords(ctx)
		if err != nil {
			return nil, store.PolicySummary{}, err
		}
		now := time.Now()
		f := evaluateStaleRecords(addresses, settings, now)
		f = append(f, evaluateStaleRecords(devices, settings, now)...)
		label := fmt.Sprintf("Stale records (not seen in %d days)", durationDays(settings.StaleAfter))
		groups = append(groups, store.PolicyFindingGroup{Check: checkStaleRecords, Label: label, Findings: f})
		all = append(all, f...)
	}

	if settings.CheckServices {
		discoveries, err := a.store.PolicyDiscoveryRecords(ctx)
		if err != nil {
			return nil, store.PolicySummary{}, err
		}
		f := evaluateUnmanagedServices(discoveries)
		groups = append(groups, store.PolicyFindingGroup{Check: checkUnmanagedServices, Label: "Unmanaged & conflicting services", Findings: f})
		all = append(all, f...)
	}

	return groups, summarizeFindings(all), nil
}

// policyIndex renders the read-only Policy / Health view. Any signed-in user
// (including a viewer) may see it; it makes no changes, so there is no CSRF or
// audit here.
func (a *App) policyIndex(w http.ResponseWriter, r *http.Request) {
	session, ok := a.requireSession(w, r)
	if !ok {
		return
	}
	groups, summary, err := a.computePolicy(r.Context())
	if err != nil {
		a.logger.Error("compute policy", "error", err)
		http.Error(w, "Unable to evaluate policy", http.StatusInternalServerError)
		return
	}
	_ = ui.Render(w, "policy.html", ui.PageData{
		Title:         "Policy",
		User:          session.User,
		CSRF:          session.CSRFToken,
		PolicyGroups:  groups,
		PolicySummary: summary,
		ActiveNav:     "policy",
	})
}

// settingsPolicy renders the admin-only Policy settings tab.
func (a *App) settingsPolicy(w http.ResponseWriter, r *http.Request) {
	session, ok := a.requireAdmin(w, r)
	if !ok {
		return
	}
	a.renderPolicyTab(w, r, session, a.policySettings().formValues(), "", policyNotice(r))
}

func (a *App) settingsPolicyUpdate(w http.ResponseWriter, r *http.Request) {
	session, ok := a.requireAdmin(w, r)
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
	settings, err := parsePolicySettingsForm(r.PostForm)
	if err != nil {
		a.renderPolicyTab(w, r, session, submittedPolicyForm(r.PostForm), err.Error(), "")
		return
	}
	if err := a.store.SetAppSettings(r.Context(), settings.toMap()); err != nil {
		a.logger.Error("save app settings", "error", err)
		a.renderPolicyTab(w, r, session, submittedPolicyForm(r.PostForm), "Unable to save settings. Please try again.", "")
		return
	}
	a.setPolicySettings(settings)
	a.auditMeta(r, &session.User.ID, "settings.policy.updated", "settings", "policy", settings.toMap())
	http.Redirect(w, r, "/settings/policy?notice=saved", http.StatusSeeOther)
}

func (a *App) renderPolicyTab(w http.ResponseWriter, r *http.Request, session store.Session, form map[string]string, errMsg, notice string) {
	_ = ui.Render(w, "settings.html", ui.PageData{
		Title:          "Settings",
		User:           session.User,
		CSRF:           session.CSRFToken,
		Error:          errMsg,
		SuccessMessage: notice,
		Form:           form,
		ActiveNav:      "settings",
		ActiveTab:      "policy",
	})
}

func policyNotice(r *http.Request) string {
	if r.URL.Query().Get("notice") == "saved" {
		return "Policy settings saved."
	}
	return ""
}
