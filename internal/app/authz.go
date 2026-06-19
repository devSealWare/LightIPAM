package app

import (
	"net/http"

	"github.com/devSealWare/LightIPAM/internal/store"
	"github.com/devSealWare/LightIPAM/internal/ui"
)

// canWrite reports whether a role may perform state-changing requests. Today the
// model is two roles — admin (read/write) and viewer (read-only operator) — so a
// viewer is blocked from every unsafe-method request except the auth allowlist.
func canWrite(role string) bool {
	return role == store.RoleAdmin
}

// publicWritePath lists the unsafe-method endpoints a not-yet-authorized user
// must still reach: authentication and sign-out. Everything else under an
// unsafe method requires a writer role.
func publicWritePath(path string) bool {
	switch path {
	case "/login", "/logout", "/bootstrap":
		return true
	default:
		return false
	}
}

// isAccountPath reports whether a path is a per-user self-service account
// action (password change, MFA enrollment). These writes operate only on the
// requesting user's own account, so any signed-in user — including a viewer —
// may perform them.
func isAccountPath(path string) bool {
	return path == "/account" || len(path) > len("/account/") && path[:len("/account/")] == "/account/"
}

// safeMethod reports whether an HTTP method is read-only (never mutates state).
func safeMethod(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	default:
		return false
	}
}

// authorize is the role middleware. Read-only requests always pass. For an
// unsafe method, an authenticated viewer is rejected with 403 before the handler
// runs; unauthenticated requests pass through so the handler's own session check
// redirects to login. Self-service account writes are allowed for any signed-in
// user via the /account/ allowlist.
func (a *App) authorize(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if safeMethod(r.Method) || publicWritePath(r.URL.Path) || isAccountPath(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}
		session, ok := a.currentSession(r)
		if ok && !canWrite(session.User.Role) {
			a.renderForbidden(w, session)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// requireAdmin loads the session and ensures the user is an admin, rendering a
// 403 otherwise. Admin-only areas (Settings, user management) use it for read
// requests too, so a viewer never sees instance configuration.
func (a *App) requireAdmin(w http.ResponseWriter, r *http.Request) (store.Session, bool) {
	session, ok := a.requireSession(w, r)
	if !ok {
		return store.Session{}, false
	}
	if !session.User.IsAdmin {
		a.renderForbidden(w, session)
		return store.Session{}, false
	}
	return session, true
}

// renderForbidden shows a 403 page within the app shell.
func (a *App) renderForbidden(w http.ResponseWriter, session store.Session) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusForbidden)
	_ = ui.Render(w, "forbidden.html", ui.PageData{
		Title: "Not allowed",
		User:  session.User,
		CSRF:  session.CSRFToken,
	})
}
