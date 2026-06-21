package app

import (
	"net/http"
	"strconv"

	"github.com/devSealWare/LightIPAM/internal/auth"
	"github.com/devSealWare/LightIPAM/internal/store"
	"github.com/devSealWare/LightIPAM/internal/ui"
)

// accountIndex is the per-user self-service page: profile, password change,
// two-factor status, and the user's own active sessions. Available to every
// signed-in user, including read-only viewers.
func (a *App) accountIndex(w http.ResponseWriter, r *http.Request) {
	session, ok := a.requireSession(w, r)
	if !ok {
		return
	}
	a.renderAccount(w, r, session, "", accountNotice(r))
}

func (a *App) accountChangePassword(w http.ResponseWriter, r *http.Request) {
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
	current := r.FormValue("current_password")
	next := r.FormValue("new_password")
	confirm := r.FormValue("confirm_password")

	user, err := a.store.GetUser(r.Context(), session.User.ID)
	if err != nil {
		http.Error(w, "Unable to load account", http.StatusInternalServerError)
		return
	}
	if !auth.VerifyPassword(user.PasswordHash, current) {
		a.renderAccount(w, r, session, "Your current password is incorrect.", "")
		return
	}
	if len(next) < minPasswordLength {
		a.renderAccount(w, r, session, "New password must be at least 12 characters.", "")
		return
	}
	if next != confirm {
		a.renderAccount(w, r, session, "The new passwords do not match.", "")
		return
	}
	hash, err := auth.HashPassword(next)
	if err != nil {
		http.Error(w, "Unable to secure password", http.StatusInternalServerError)
		return
	}
	if err := a.store.SetUserPassword(r.Context(), session.User.ID, hash); err != nil {
		a.logger.Error("change password", "error", err)
		http.Error(w, "Unable to change password", http.StatusInternalServerError)
		return
	}
	// Sign the user's other sessions out so the old password can't ride them.
	if _, err := a.store.DeleteOtherUserSessions(r.Context(), session.User.ID, session.ID); err != nil {
		a.logger.Error("revoke other sessions", "error", err)
	}
	a.audit(r, &session.User.ID, "auth.password.changed", "user", session.User.ID)
	http.Redirect(w, r, "/account?notice=password", http.StatusSeeOther)
}

func (a *App) accountLogoutAll(w http.ResponseWriter, r *http.Request) {
	session, ok := a.requireSession(w, r)
	if !ok {
		return
	}
	if !a.verifySessionCSRF(r, session) {
		http.Error(w, "Invalid form token", http.StatusForbidden)
		return
	}
	revoked, err := a.store.DeleteOtherUserSessions(r.Context(), session.User.ID, session.ID)
	if err != nil {
		a.logger.Error("revoke other sessions", "error", err)
		http.Error(w, "Unable to revoke sessions", http.StatusInternalServerError)
		return
	}
	a.auditMeta(r, &session.User.ID, "session.revoked_all", "user", session.User.ID, map[string]string{
		"scope":   "others",
		"revoked": strconv.FormatInt(revoked, 10),
	})
	http.Redirect(w, r, "/account?notice=revoked", http.StatusSeeOther)
}

// renderAccount renders the account page with the user's sessions and MFA state.
func (a *App) renderAccount(w http.ResponseWriter, r *http.Request, session store.Session, errMsg, notice string) {
	data, ok := a.accountPageData(w, r, session)
	if !ok {
		return
	}
	data.Error = errMsg
	data.SuccessMessage = notice
	_ = ui.Render(w, "account.html", data)
}

// accountPageData gathers the account page's per-user state (sessions, MFA status,
// API tokens). It writes an error response and returns ok=false on failure.
func (a *App) accountPageData(w http.ResponseWriter, r *http.Request, session store.Session) (ui.PageData, bool) {
	sessions, err := a.store.ListUserSessions(r.Context(), session.User.ID, a.idleCutoff())
	if err != nil {
		a.logger.Error("list user sessions", "error", err)
		http.Error(w, "Unable to load sessions", http.StatusInternalServerError)
		return ui.PageData{}, false
	}
	enabled, err := a.store.TOTPEnabled(r.Context(), session.User.ID)
	if err != nil {
		a.logger.Error("totp enabled", "error", err)
	}
	tokens, err := a.store.ListAPITokens(r.Context(), session.User.ID)
	if err != nil {
		a.logger.Error("list api tokens", "error", err)
	}
	return ui.PageData{
		Title:            "Your account",
		User:             session.User,
		CSRF:             session.CSRFToken,
		Sessions:         sessions,
		CurrentSessionID: session.ID,
		MFAEnabled:       enabled,
		APITokens:        tokens,
		ActiveNav:        "account",
	}, true
}

// accountNotice maps the post-redirect ?notice marker to a banner message.
func accountNotice(r *http.Request) string {
	switch r.URL.Query().Get("notice") {
	case "password":
		return "Password changed; your other sessions were signed out."
	case "revoked":
		return "Signed out your other sessions."
	case "mfa_off":
		return "Two-factor authentication is off."
	case "token_revoked":
		return "API token revoked."
	default:
		return ""
	}
}
