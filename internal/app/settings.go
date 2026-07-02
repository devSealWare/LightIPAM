package app

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/devSealWare/LightIPAM/internal/store"
	"github.com/devSealWare/LightIPAM/internal/ui"
)

// SecuritySettings is the runtime-tunable auth + session policy. Boot defaults
// come from env (config); an admin overrides them from the Settings page, which
// persists them in app_settings. The app keeps the active values cached.
type SecuritySettings struct {
	LoginMaxAttempts             int
	LoginWindow                  time.Duration
	LoginLockout                 time.Duration
	SessionAbsoluteTimeout       time.Duration
	SessionIdleTimeout           time.Duration
	LogoutEverywhereKeepsCurrent bool
}

// app_settings keys for the persisted security policy.
const (
	settingLoginMaxAttempts   = "login_max_attempts"
	settingLoginWindow        = "login_window"
	settingLoginLockout       = "login_lockout"
	settingSessionAbsolute    = "session_absolute_timeout"
	settingSessionIdle        = "session_idle_timeout"
	settingLogoutKeepsCurrent = "logout_everywhere_keeps_current"
)

func (a *App) defaultSecuritySettings() SecuritySettings {
	return SecuritySettings{
		LoginMaxAttempts:             a.cfg.LoginMaxAttempts,
		LoginWindow:                  a.cfg.LoginWindow,
		LoginLockout:                 a.cfg.LoginLockout,
		SessionAbsoluteTimeout:       a.cfg.SessionAbsoluteTimeout,
		SessionIdleTimeout:           a.cfg.SessionIdleTimeout,
		LogoutEverywhereKeepsCurrent: a.cfg.LogoutEverywhereKeepsCurrent,
	}
}

// loadSettings overlays any DB-stored security settings onto the env defaults
// and caches the result. A missing/invalid stored value falls back to its
// default, so a partially-populated table never yields an unsafe policy.
func (a *App) loadSettings(ctx context.Context) {
	stored, err := a.store.GetAppSettings(ctx)
	if err != nil {
		a.logger.Error("load app settings", "error", err)
		stored = nil
	}
	a.setSettings(a.mergeSettings(stored))
	a.setPolicySettings(a.mergePolicySettings(stored))
	a.loadOIDCSettings(ctx, stored)
}

func (a *App) mergeSettings(stored map[string]string) SecuritySettings {
	s := a.defaultSecuritySettings()
	if n, err := strconv.Atoi(stored[settingLoginMaxAttempts]); err == nil && n > 0 {
		s.LoginMaxAttempts = n
	}
	if d, err := time.ParseDuration(stored[settingLoginWindow]); err == nil && d > 0 {
		s.LoginWindow = d
	}
	if d, err := time.ParseDuration(stored[settingLoginLockout]); err == nil && d > 0 {
		s.LoginLockout = d
	}
	if d, err := time.ParseDuration(stored[settingSessionAbsolute]); err == nil && d > 0 {
		s.SessionAbsoluteTimeout = d
	}
	if d, err := time.ParseDuration(stored[settingSessionIdle]); err == nil && d > 0 {
		s.SessionIdleTimeout = d
	}
	if v, ok := stored[settingLogoutKeepsCurrent]; ok {
		s.LogoutEverywhereKeepsCurrent = v == "true"
	}
	return s
}

func (a *App) securitySettings() SecuritySettings {
	a.settingsMu.RLock()
	defer a.settingsMu.RUnlock()
	return a.settings
}

func (a *App) setSettings(s SecuritySettings) {
	a.settingsMu.Lock()
	defer a.settingsMu.Unlock()
	a.settings = s
}

// toMap serializes settings for app_settings (canonical Go-duration strings).
func (s SecuritySettings) toMap() map[string]string {
	return map[string]string{
		settingLoginMaxAttempts:   strconv.Itoa(s.LoginMaxAttempts),
		settingLoginWindow:        s.LoginWindow.String(),
		settingLoginLockout:       s.LoginLockout.String(),
		settingSessionAbsolute:    s.SessionAbsoluteTimeout.String(),
		settingSessionIdle:        s.SessionIdleTimeout.String(),
		settingLogoutKeepsCurrent: strconv.FormatBool(s.LogoutEverywhereKeepsCurrent),
	}
}

// formValues renders the settings as the Form map the security tab pre-fills,
// with durations expressed in the units the form edits.
func (s SecuritySettings) formValues() map[string]string {
	form := map[string]string{
		"login_max_attempts":     strconv.Itoa(s.LoginMaxAttempts),
		"login_window_minutes":   strconv.Itoa(durationMinutes(s.LoginWindow)),
		"login_lockout_minutes":  strconv.Itoa(durationMinutes(s.LoginLockout)),
		"session_idle_minutes":   strconv.Itoa(durationMinutes(s.SessionIdleTimeout)),
		"session_absolute_hours": strconv.Itoa(durationHours(s.SessionAbsoluteTimeout)),
	}
	if s.LogoutEverywhereKeepsCurrent {
		form["logout_keeps_current"] = "on"
	}
	return form
}

// submittedSecurityForm echoes the raw submitted values back into the Form map
// so an invalid submission re-renders with what the operator typed.
func submittedSecurityForm(form url.Values) map[string]string {
	out := map[string]string{
		"login_max_attempts":     strings.TrimSpace(form.Get("login_max_attempts")),
		"login_window_minutes":   strings.TrimSpace(form.Get("login_window_minutes")),
		"login_lockout_minutes":  strings.TrimSpace(form.Get("login_lockout_minutes")),
		"session_idle_minutes":   strings.TrimSpace(form.Get("session_idle_minutes")),
		"session_absolute_hours": strings.TrimSpace(form.Get("session_absolute_hours")),
	}
	if form.Get("logout_keeps_current") != "" {
		out["logout_keeps_current"] = "on"
	}
	return out
}

// parseSecuritySettingsForm validates and converts the security-tab form into a
// SecuritySettings. Pure so it is unit-tested without a request or DB.
func parseSecuritySettingsForm(form url.Values) (SecuritySettings, error) {
	maxAttempts, err := intInRange(form.Get("login_max_attempts"), 1, 100)
	if err != nil {
		return SecuritySettings{}, errors.New("Maximum failed attempts must be a whole number between 1 and 100.")
	}
	window, err := minutesInRange(form.Get("login_window_minutes"), 1, 1440)
	if err != nil {
		return SecuritySettings{}, errors.New("Attempt window must be between 1 and 1440 minutes.")
	}
	lockout, err := minutesInRange(form.Get("login_lockout_minutes"), 1, 1440)
	if err != nil {
		return SecuritySettings{}, errors.New("Lockout duration must be between 1 and 1440 minutes.")
	}
	idle, err := minutesInRange(form.Get("session_idle_minutes"), 1, 10080)
	if err != nil {
		return SecuritySettings{}, errors.New("Idle timeout must be between 1 and 10080 minutes.")
	}
	absolute, err := hoursInRange(form.Get("session_absolute_hours"), 1, 720)
	if err != nil {
		return SecuritySettings{}, errors.New("Absolute timeout must be between 1 and 720 hours.")
	}
	if lockout > window {
		return SecuritySettings{}, errors.New("Attempt window must be at least as long as the lockout duration.")
	}
	return SecuritySettings{
		LoginMaxAttempts:             maxAttempts,
		LoginWindow:                  window,
		LoginLockout:                 lockout,
		SessionIdleTimeout:           idle,
		SessionAbsoluteTimeout:       absolute,
		LogoutEverywhereKeepsCurrent: form.Get("logout_keeps_current") != "",
	}, nil
}

var errOutOfRange = errors.New("value out of range")

func intInRange(value string, min, max int) (int, error) {
	n, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil || n < min || n > max {
		return 0, errOutOfRange
	}
	return n, nil
}

func minutesInRange(value string, min, max int) (time.Duration, error) {
	n, err := intInRange(value, min, max)
	if err != nil {
		return 0, err
	}
	return time.Duration(n) * time.Minute, nil
}

func hoursInRange(value string, min, max int) (time.Duration, error) {
	n, err := intInRange(value, min, max)
	if err != nil {
		return 0, err
	}
	return time.Duration(n) * time.Hour, nil
}

func durationMinutes(d time.Duration) int {
	if m := int(d / time.Minute); m >= 1 {
		return m
	}
	return 1
}

func durationHours(d time.Duration) int {
	if h := int(d / time.Hour); h >= 1 {
		return h
	}
	return 1
}

// settingsDiscovery renders the admin-only Discovery settings tab (ADR 0030):
// today a single toggle, the opt-in gold-confidence serial auto-link. Unlike the
// hot-path security settings the value is not cached — the store reads it at
// import time, so a save takes effect immediately everywhere.
func (a *App) settingsDiscovery(w http.ResponseWriter, r *http.Request) {
	session, ok := a.requireAdmin(w, r)
	if !ok {
		return
	}
	stored, err := a.store.GetAppSettings(r.Context())
	if err != nil {
		a.logger.Error("load app settings", "error", err)
		http.Error(w, "Unable to load settings", http.StatusInternalServerError)
		return
	}
	a.renderDiscoveryTab(w, r, session, discoverySettingsForm(stored), "", discoveryNotice(r))
}

func (a *App) settingsDiscoveryUpdate(w http.ResponseWriter, r *http.Request) {
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
	values := parseDiscoverySettingsForm(r.PostForm)
	if err := a.store.SetAppSettings(r.Context(), values); err != nil {
		a.logger.Error("save app settings", "error", err)
		a.renderDiscoveryTab(w, r, session, submittedDiscoveryForm(r.PostForm), "Unable to save settings. Please try again.", "")
		return
	}
	a.auditMeta(r, &session.User.ID, "settings.discovery.updated", "settings", "discovery", values)
	http.Redirect(w, r, "/settings/discovery?notice=saved", http.StatusSeeOther)
}

func (a *App) renderDiscoveryTab(w http.ResponseWriter, r *http.Request, session store.Session, form map[string]string, errMsg, notice string) {
	_ = ui.Render(w, "settings.html", ui.PageData{
		Title:          "Settings",
		Error:          errMsg,
		SuccessMessage: notice,
		User:           session.User,
		CSRF:           session.CSRFToken,
		Form:           form,
		ActiveNav:      "settings",
		ActiveTab:      "discovery",
	})
}

// discoverySettingsForm renders the stored discovery settings as the checkbox
// Form map; parseDiscoverySettingsForm is its inverse (a checkbox posts "on" or
// nothing, persisted as "true"/"false"). Both are pure.
func discoverySettingsForm(stored map[string]string) map[string]string {
	form := map[string]string{}
	if stored[store.SettingDeviceLinkAutoSerial] == "true" {
		form["auto_link_serial"] = "on"
	}
	return form
}

func parseDiscoverySettingsForm(form url.Values) map[string]string {
	return map[string]string{
		store.SettingDeviceLinkAutoSerial: strconv.FormatBool(form.Get("auto_link_serial") != ""),
	}
}

func submittedDiscoveryForm(form url.Values) map[string]string {
	out := map[string]string{}
	if form.Get("auto_link_serial") != "" {
		out["auto_link_serial"] = "on"
	}
	return out
}

func discoveryNotice(r *http.Request) string {
	if r.URL.Query().Get("notice") == "saved" {
		return "Discovery settings saved."
	}
	return ""
}
