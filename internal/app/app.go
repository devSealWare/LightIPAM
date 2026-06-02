package app

import (
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/devSealWare/LightIPAM/internal/auth"
	"github.com/devSealWare/LightIPAM/internal/config"
	"github.com/devSealWare/LightIPAM/internal/store"
	"github.com/devSealWare/LightIPAM/internal/ui"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	sessionCookie = "lightipam_session"
	csrfCookie    = "lightipam_csrf"
)

type Options struct {
	Config config.Config
	DB     *pgxpool.Pool
	Logger *slog.Logger
}

type App struct {
	cfg    config.Config
	store  *store.Store
	logger *slog.Logger
}

func New(options Options) http.Handler {
	app := &App{
		cfg:    options.Config,
		store:  store.New(options.DB),
		logger: options.Logger,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", app.health)
	mux.HandleFunc("GET /static/app.css", ui.StaticCSS)
	mux.HandleFunc("GET /", app.dashboard)
	mux.HandleFunc("GET /bootstrap", app.bootstrapForm)
	mux.HandleFunc("POST /bootstrap", app.bootstrapSubmit)
	mux.HandleFunc("GET /login", app.loginForm)
	mux.HandleFunc("POST /login", app.loginSubmit)
	mux.HandleFunc("POST /logout", app.logout)

	return securityHeaders(mux)
}

func (a *App) health(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"status":"ok","service":"light-ipam"}`))
}

func (a *App) dashboard(w http.ResponseWriter, r *http.Request) {
	if a.needsBootstrap(r) {
		http.Redirect(w, r, "/bootstrap", http.StatusSeeOther)
		return
	}

	session, ok := a.requireSession(w, r)
	if !ok {
		return
	}

	_ = ui.Render(w, "dashboard.html", ui.PageData{
		Title: "Dashboard",
		User:  session.User,
		CSRF:  session.CSRFToken,
	})
}

func (a *App) bootstrapForm(w http.ResponseWriter, r *http.Request) {
	if !a.needsBootstrap(r) {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	csrf, err := auth.RandomToken(32)
	if err != nil {
		http.Error(w, "Unable to create form token", http.StatusInternalServerError)
		return
	}
	a.setCSRFCookie(w, csrf)
	_ = ui.Render(w, "bootstrap.html", ui.PageData{
		Title: "Create Admin",
		CSRF:  csrf,
	})
}

func (a *App) bootstrapSubmit(w http.ResponseWriter, r *http.Request) {
	if !a.needsBootstrap(r) {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if !a.verifyFormCSRF(r) {
		http.Error(w, "Invalid form token", http.StatusForbidden)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form", http.StatusBadRequest)
		return
	}

	username := strings.TrimSpace(r.FormValue("username"))
	displayName := strings.TrimSpace(r.FormValue("display_name"))
	password := r.FormValue("password")
	if displayName == "" {
		displayName = username
	}
	if username == "" || len(password) < 12 {
		a.renderBootstrapError(w, "Use a username and a password with at least 12 characters.")
		return
	}

	passwordHash, err := auth.HashPassword(password)
	if err != nil {
		http.Error(w, "Unable to secure password", http.StatusInternalServerError)
		return
	}

	user, err := a.store.CreateAdmin(r.Context(), username, displayName, passwordHash)
	if err != nil {
		a.logger.Error("create bootstrap admin", "error", err)
		a.renderBootstrapError(w, "Unable to create the admin account. Try a different username.")
		return
	}

	if err := a.store.CreateAuditLog(r.Context(), &user.ID, "admin.bootstrap.created", "user", user.ID, "{}"); err != nil {
		a.logger.Error("create audit log", "error", err)
	}

	a.establishSession(w, r, user.ID)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (a *App) loginForm(w http.ResponseWriter, r *http.Request) {
	if a.needsBootstrap(r) {
		http.Redirect(w, r, "/bootstrap", http.StatusSeeOther)
		return
	}
	csrf, err := auth.RandomToken(32)
	if err != nil {
		http.Error(w, "Unable to create form token", http.StatusInternalServerError)
		return
	}
	a.setCSRFCookie(w, csrf)
	_ = ui.Render(w, "login.html", ui.PageData{
		Title: "Sign In",
		CSRF:  csrf,
	})
}

func (a *App) loginSubmit(w http.ResponseWriter, r *http.Request) {
	if !a.verifyFormCSRF(r) {
		http.Error(w, "Invalid form token", http.StatusForbidden)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form", http.StatusBadRequest)
		return
	}

	username := strings.TrimSpace(r.FormValue("username"))
	password := r.FormValue("password")
	user, err := a.store.FindUserByUsername(r.Context(), username)
	if err != nil || !auth.VerifyPassword(user.PasswordHash, password) {
		_ = ui.Render(w, "login.html", ui.PageData{
			Title: "Sign In",
			Error: "The username or password is incorrect.",
			CSRF:  r.FormValue("csrf_token"),
		})
		return
	}

	if err := a.store.CreateAuditLog(r.Context(), &user.ID, "auth.login", "user", user.ID, "{}"); err != nil {
		a.logger.Error("create audit log", "error", err)
	}

	a.establishSession(w, r, user.ID)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (a *App) logout(w http.ResponseWriter, r *http.Request) {
	session, ok := a.currentSession(r)
	if ok && r.FormValue("csrf_token") == session.CSRFToken {
		if err := a.store.DeleteSession(r.Context(), session.ID); err != nil {
			a.logger.Error("delete session", "error", err)
		}
		if err := a.store.CreateAuditLog(r.Context(), &session.User.ID, "auth.logout", "user", session.User.ID, "{}"); err != nil {
			a.logger.Error("create audit log", "error", err)
		}
	}
	a.clearSessionCookie(w)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (a *App) needsBootstrap(r *http.Request) bool {
	count, err := a.store.CountAdmins(r.Context())
	if err != nil {
		a.logger.Error("count admins", "error", err)
		return false
	}
	return count == 0
}

func (a *App) requireSession(w http.ResponseWriter, r *http.Request) (store.Session, bool) {
	session, ok := a.currentSession(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return store.Session{}, false
	}
	return session, true
}

func (a *App) currentSession(r *http.Request) (store.Session, bool) {
	cookie, err := r.Cookie(sessionCookie)
	if err != nil || cookie.Value == "" {
		return store.Session{}, false
	}
	session, err := a.store.GetSession(r.Context(), cookie.Value)
	if err != nil {
		if !errors.Is(err, store.ErrNotFound) {
			a.logger.Error("get session", "error", err)
		}
		return store.Session{}, false
	}
	return session, true
}

func (a *App) establishSession(w http.ResponseWriter, r *http.Request, userID string) {
	expiresAt := time.Now().Add(12 * time.Hour)
	session, err := a.store.CreateSession(r.Context(), userID, expiresAt)
	if err != nil {
		a.logger.Error("create session", "error", err)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    session.ID,
		Path:     "/",
		Expires:  expiresAt,
		HttpOnly: true,
		Secure:   a.cfg.CookieSecure,
		SameSite: http.SameSiteLaxMode,
	})
}

func (a *App) setCSRFCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     csrfCookie,
		Value:    token,
		Path:     "/",
		MaxAge:   600,
		HttpOnly: true,
		Secure:   a.cfg.CookieSecure,
		SameSite: http.SameSiteLaxMode,
	})
}

func (a *App) clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   a.cfg.CookieSecure,
		SameSite: http.SameSiteLaxMode,
	})
}

func (a *App) verifyFormCSRF(r *http.Request) bool {
	cookie, err := r.Cookie(csrfCookie)
	if err != nil {
		return false
	}
	return cookie.Value != "" && cookie.Value == r.FormValue("csrf_token")
}

func (a *App) renderBootstrapError(w http.ResponseWriter, message string) {
	csrf, _ := auth.RandomToken(32)
	a.setCSRFCookie(w, csrf)
	_ = ui.Render(w, "bootstrap.html", ui.PageData{
		Title: "Create Admin",
		Error: message,
		CSRF:  csrf,
	})
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self'; img-src 'self' data:; form-action 'self'; frame-ancestors 'none'")
		w.Header().Set("Referrer-Policy", "same-origin")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		next.ServeHTTP(w, r)
	})
}
