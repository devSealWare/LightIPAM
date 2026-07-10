package app

import (
	"net/http"
	"strings"

	"github.com/devSealWare/LightIPAM/internal/auth"
	"github.com/devSealWare/LightIPAM/internal/ui"
)

// apiTokenPrefix labels generated tokens so they are recognizable in logs/configs
// (without revealing the secret, which is the random suffix).
const apiTokenPrefix = "lipam_"

// accountTokenCreate mints a new API token for the signed-in user and shows the
// plaintext once. Restricted to admins (finding 0004): although a token
// inherits its creator's role and a viewer's token would be read-only, token
// creation is gated on the writer role as a matter of policy so operators can
// bound the number of long-lived credentials that can touch /api/v1.
func (a *App) accountTokenCreate(w http.ResponseWriter, r *http.Request) {
	session, ok := a.requireSession(w, r)
	if !ok {
		return
	}
	if !canWrite(session.User.Role) {
		http.Error(w, "Only admins can create API tokens.", http.StatusForbidden)
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
	name := strings.TrimSpace(r.FormValue("name"))
	if name == "" {
		a.renderAccount(w, r, session, "Give the token a name so you can recognize it later.", "")
		return
	}
	secret, err := auth.RandomToken(24)
	if err != nil {
		http.Error(w, "Unable to generate token", http.StatusInternalServerError)
		return
	}
	token := apiTokenPrefix + secret
	if _, err := a.store.CreateAPIToken(r.Context(), session.User.ID, name, auth.HashToken(token)); err != nil {
		a.logger.Error("create api token", "error", err)
		a.renderAccount(w, r, session, "Unable to create the token. Please try again.", "")
		return
	}
	a.audit(r, &session.User.ID, "auth.api_token.created", "user", session.User.ID)

	// Show the plaintext once, inline (never persisted or re-shown).
	data, ok := a.accountPageData(w, r, session)
	if !ok {
		return
	}
	data.NewAPIToken = token
	data.SuccessMessage = "Token created. Copy it now — it is shown only once."
	_ = ui.Render(w, "account.html", data)
}

// accountTokenDelete revokes one of the user's own tokens.
func (a *App) accountTokenDelete(w http.ResponseWriter, r *http.Request) {
	session, ok := a.requireSession(w, r)
	if !ok {
		return
	}
	if !a.verifySessionCSRF(r, session) {
		http.Error(w, "Invalid form token", http.StatusForbidden)
		return
	}
	if err := a.store.DeleteAPIToken(r.Context(), r.PathValue("id"), session.User.ID); err != nil {
		a.logger.Error("delete api token", "error", err)
	} else {
		a.audit(r, &session.User.ID, "auth.api_token.revoked", "user", session.User.ID)
	}
	http.Redirect(w, r, "/account?notice=token_revoked", http.StatusSeeOther)
}
