package app

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/devSealWare/LightIPAM/internal/store"
	"github.com/devSealWare/LightIPAM/internal/ui"
)

// OIDCSettings is the runtime-tunable SSO configuration. The client secret is
// stored sealed (never plaintext) in app_settings; everything else is plain
// configuration. Env values seed the boot defaults.
type OIDCSettings struct {
	Enabled       bool
	Issuer        string
	ClientID      string
	ClientSecret  string // plaintext in memory; persisted sealed
	BaseURL       string // external base URL for the redirect (e.g. https://ipam.example.com)
	UsernameClaim string
	AutoProvision bool
}

// app_settings keys for OIDC. The secret is stored under a *_sealed key so it is
// obvious in the table that the value is ciphertext.
const (
	settingOIDCEnabled       = "oidc_enabled"
	settingOIDCIssuer        = "oidc_issuer"
	settingOIDCClientID      = "oidc_client_id"
	settingOIDCClientSecret  = "oidc_client_secret_sealed"
	settingOIDCBaseURL       = "oidc_base_url"
	settingOIDCUsernameClaim = "oidc_username_claim"
	settingOIDCAutoProvision = "oidc_auto_provision"
)

func (a *App) defaultOIDCSettings() OIDCSettings {
	claim := a.cfg.OIDCUsernameClaim
	if claim == "" {
		claim = "preferred_username"
	}
	return OIDCSettings{
		Enabled:       a.cfg.OIDCEnabled,
		Issuer:        a.cfg.OIDCIssuer,
		ClientID:      a.cfg.OIDCClientID,
		ClientSecret:  a.cfg.OIDCClientSecret,
		BaseURL:       a.cfg.OIDCBaseURL,
		UsernameClaim: claim,
		AutoProvision: a.cfg.OIDCAutoProvision,
	}
}

// loadOIDCSettings overlays stored OIDC settings (opening the sealed secret)
// onto the env defaults and caches the result.
func (a *App) loadOIDCSettings(ctx context.Context, stored map[string]string) {
	a.setOIDC(a.mergeOIDCSettings(stored))
}

func (a *App) mergeOIDCSettings(stored map[string]string) OIDCSettings {
	s := a.defaultOIDCSettings()
	if v, ok := stored[settingOIDCEnabled]; ok {
		s.Enabled = v == "true"
	}
	if v, ok := stored[settingOIDCIssuer]; ok {
		s.Issuer = v
	}
	if v, ok := stored[settingOIDCClientID]; ok {
		s.ClientID = v
	}
	if v, ok := stored[settingOIDCBaseURL]; ok {
		s.BaseURL = v
	}
	if v, ok := stored[settingOIDCUsernameClaim]; ok && v != "" {
		s.UsernameClaim = v
	}
	if v, ok := stored[settingOIDCAutoProvision]; ok {
		s.AutoProvision = v == "true"
	}
	if sealed, ok := stored[settingOIDCClientSecret]; ok && sealed != "" && a.sealer != nil {
		if plain, err := a.sealer.Open(sealed); err == nil {
			s.ClientSecret = plain
		}
	}
	return s
}

func (a *App) oidcSettings() OIDCSettings {
	a.settingsMu.RLock()
	defer a.settingsMu.RUnlock()
	return a.oidc
}

func (a *App) setOIDC(s OIDCSettings) {
	a.settingsMu.Lock()
	defer a.settingsMu.Unlock()
	a.oidc = s
	// A settings change invalidates any cached provider so the next login rebuilds.
	a.oidcProvider = nil
}

// redirectURL returns the OIDC callback URL the IdP must redirect back to.
func (s OIDCSettings) redirectURL() string {
	base := strings.TrimRight(s.BaseURL, "/")
	if base == "" {
		return ""
	}
	return base + "/auth/oidc/callback"
}

// configured reports whether OIDC is enabled and has the minimum fields set.
func (s OIDCSettings) configured() bool {
	return s.Enabled && s.Issuer != "" && s.ClientID != "" && s.BaseURL != ""
}

// toMap serializes OIDC settings for app_settings, sealing the client secret.
// A blank secret keeps the existing stored value (passed in as keepSecret).
func (s OIDCSettings) toMap(sealedSecret string) map[string]string {
	return map[string]string{
		settingOIDCEnabled:       boolString(s.Enabled),
		settingOIDCIssuer:        s.Issuer,
		settingOIDCClientID:      s.ClientID,
		settingOIDCClientSecret:  sealedSecret,
		settingOIDCBaseURL:       s.BaseURL,
		settingOIDCUsernameClaim: s.UsernameClaim,
		settingOIDCAutoProvision: boolString(s.AutoProvision),
	}
}

func boolString(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// oidcFormValues renders the OIDC settings as the Form map the Authentication
// tab pre-fills. The client secret is never echoed back; a placeholder marks
// that one is configured.
func (s OIDCSettings) oidcFormValues() map[string]string {
	form := map[string]string{
		"oidc_issuer":         s.Issuer,
		"oidc_client_id":      s.ClientID,
		"oidc_base_url":       s.BaseURL,
		"oidc_username_claim": s.UsernameClaim,
	}
	if s.Enabled {
		form["oidc_enabled"] = "on"
	}
	if s.AutoProvision {
		form["oidc_auto_provision"] = "on"
	}
	if s.ClientSecret != "" {
		form["oidc_secret_set"] = "1"
	}
	return form
}

// parseOIDCSettingsForm validates and converts the Authentication-tab form. It
// is pure (no request/DB) so it is unit-tested. The returned ClientSecret is the
// submitted plaintext (empty means "keep the existing one"); the caller seals it.
func parseOIDCSettingsForm(form url.Values) (OIDCSettings, error) {
	enabled := form.Get("oidc_enabled") != ""
	issuer := strings.TrimSpace(form.Get("oidc_issuer"))
	clientID := strings.TrimSpace(form.Get("oidc_client_id"))
	baseURL := strings.TrimSpace(form.Get("oidc_base_url"))
	claim := strings.TrimSpace(form.Get("oidc_username_claim"))
	if claim == "" {
		claim = "preferred_username"
	}
	if enabled {
		if issuer == "" || clientID == "" || baseURL == "" {
			return OIDCSettings{}, errors.New("Issuer URL, client ID, and base URL are required to enable SSO.")
		}
		if !validHTTPSURL(issuer) {
			return OIDCSettings{}, errors.New("Issuer must be an https:// URL.")
		}
		if !validHTTPURL(baseURL) {
			return OIDCSettings{}, errors.New("Base URL must be an http(s):// URL.")
		}
	}
	return OIDCSettings{
		Enabled:       enabled,
		Issuer:        strings.TrimRight(issuer, "/"),
		ClientID:      clientID,
		ClientSecret:  form.Get("oidc_client_secret"),
		BaseURL:       strings.TrimRight(baseURL, "/"),
		UsernameClaim: claim,
		AutoProvision: form.Get("oidc_auto_provision") != "",
	}, nil
}

func validHTTPSURL(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && u.Scheme == "https" && u.Host != ""
}

func validHTTPURL(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != ""
}

// oidcUsername chooses a local username from the ID-token claims, trying the
// configured claim, then preferred_username, then the email local-part, then
// the subject. Pure for testing.
func oidcUsername(claims map[string]any, usernameClaim string) string {
	for _, key := range []string{usernameClaim, "preferred_username", "email"} {
		if key == "" {
			continue
		}
		if v, ok := claims[key].(string); ok {
			v = strings.TrimSpace(v)
			if key == "email" {
				if at := strings.IndexByte(v, '@'); at > 0 {
					v = v[:at]
				}
			}
			if v != "" {
				return v
			}
		}
	}
	if sub, ok := claims["sub"].(string); ok {
		return strings.TrimSpace(sub)
	}
	return ""
}

// oidcDisplayName chooses a display name from the claims, falling back to the
// username.
func oidcDisplayName(claims map[string]any, username string) string {
	if v, ok := claims["name"].(string); ok && strings.TrimSpace(v) != "" {
		return strings.TrimSpace(v)
	}
	return username
}

func (a *App) settingsAuthentication(w http.ResponseWriter, r *http.Request) {
	session, ok := a.requireAdmin(w, r)
	if !ok {
		return
	}
	notice := ""
	if r.URL.Query().Get("notice") == "saved" {
		notice = "Authentication settings saved."
	}
	a.renderAuthTab(w, session, a.oidcSettings().oidcFormValues(), "", notice)
}

func (a *App) settingsAuthenticationUpdate(w http.ResponseWriter, r *http.Request) {
	session, ok := a.requireAdmin(w, r)
	if !ok {
		return
	}
	if !a.verifySessionCSRF(r, session) {
		http.Error(w, "Invalid form token", http.StatusForbidden)
		return
	}
	if a.sealer == nil {
		a.renderAuthTab(w, session, submittedAuthForm(r.PostForm), "Single sign-on needs an encryption key (APP_ENCRYPTION_KEY/APP_SECRET).", "")
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form", http.StatusBadRequest)
		return
	}
	parsed, err := parseOIDCSettingsForm(r.PostForm)
	if err != nil {
		a.renderAuthTab(w, session, submittedAuthForm(r.PostForm), err.Error(), "")
		return
	}

	stored, _ := a.store.GetAppSettings(r.Context())
	existingSealed := stored[settingOIDCClientSecret]
	sealedSecret := existingSealed
	if parsed.ClientSecret != "" {
		sealedSecret, err = a.sealer.Seal(parsed.ClientSecret)
		if err != nil {
			a.renderAuthTab(w, session, submittedAuthForm(r.PostForm), "Unable to secure the client secret.", "")
			return
		}
	} else if existingSealed != "" {
		// Keep the existing secret; load its plaintext into the cache so the
		// provider can still be built.
		parsed.ClientSecret, _ = a.sealer.Open(existingSealed)
	}
	if parsed.Enabled && parsed.ClientSecret == "" {
		a.renderAuthTab(w, session, submittedAuthForm(r.PostForm), "A client secret is required to enable SSO.", "")
		return
	}

	if err := a.store.SetAppSettings(r.Context(), parsed.toMap(sealedSecret)); err != nil {
		a.logger.Error("save oidc settings", "error", err)
		a.renderAuthTab(w, session, submittedAuthForm(r.PostForm), "Unable to save settings. Please try again.", "")
		return
	}
	a.setOIDC(parsed)
	a.auditMeta(r, &session.User.ID, "settings.authentication.updated", "settings", "authentication", map[string]string{
		"enabled": boolString(parsed.Enabled),
		"issuer":  parsed.Issuer,
	})
	http.Redirect(w, r, "/settings/authentication?notice=saved", http.StatusSeeOther)
}

// renderAuthTab renders the Settings page on its Authentication (SSO) tab.
func (a *App) renderAuthTab(w http.ResponseWriter, session store.Session, form map[string]string, errMsg, notice string) {
	if form == nil {
		form = map[string]string{}
	}
	if base := strings.TrimRight(form["oidc_base_url"], "/"); base != "" {
		form["oidc_redirect_url"] = base + "/auth/oidc/callback"
	}
	_ = ui.Render(w, "settings.html", ui.PageData{
		Title:          "Settings",
		User:           session.User,
		CSRF:           session.CSRFToken,
		Error:          errMsg,
		SuccessMessage: notice,
		Form:           form,
		ActiveNav:      "settings",
		ActiveTab:      "authentication",
	})
}

// submittedAuthForm echoes submitted Authentication-tab values back on error.
func submittedAuthForm(form url.Values) map[string]string {
	out := map[string]string{
		"oidc_issuer":         strings.TrimSpace(form.Get("oidc_issuer")),
		"oidc_client_id":      strings.TrimSpace(form.Get("oidc_client_id")),
		"oidc_base_url":       strings.TrimSpace(form.Get("oidc_base_url")),
		"oidc_username_claim": strings.TrimSpace(form.Get("oidc_username_claim")),
	}
	if form.Get("oidc_enabled") != "" {
		out["oidc_enabled"] = "on"
	}
	if form.Get("oidc_auto_provision") != "" {
		out["oidc_auto_provision"] = "on"
	}
	return out
}
