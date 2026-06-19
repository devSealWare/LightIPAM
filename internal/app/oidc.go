package app

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/devSealWare/LightIPAM/internal/auth"
	"github.com/devSealWare/LightIPAM/internal/store"
	"golang.org/x/oauth2"
)

const (
	oidcStateCookie = "lightipam_oidc"
	oidcStateTTL    = 10 * time.Minute
)

var errOIDCNotConfigured = errors.New("oidc not configured")

// oidcProvider caches a built OIDC provider/verifier for the current settings.
type oidcProvider struct {
	issuer   string
	clientID string
	redirect string
	config   oauth2.Config
	verifier *oidc.IDTokenVerifier
}

// buildOIDCProvider discovers the issuer and assembles the oauth2 config and ID
// token verifier. This performs network I/O against the issuer.
func (a *App) buildOIDCProvider(ctx context.Context, s OIDCSettings) (*oidcProvider, error) {
	provider, err := oidc.NewProvider(ctx, s.Issuer)
	if err != nil {
		return nil, fmt.Errorf("oidc discovery: %w", err)
	}
	return &oidcProvider{
		issuer:   s.Issuer,
		clientID: s.ClientID,
		redirect: s.redirectURL(),
		config: oauth2.Config{
			ClientID:     s.ClientID,
			ClientSecret: s.ClientSecret,
			Endpoint:     provider.Endpoint(),
			RedirectURL:  s.redirectURL(),
			Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
		},
		verifier: provider.Verifier(&oidc.Config{ClientID: s.ClientID}),
	}, nil
}

// getOIDCProvider returns a cached provider matching the current settings,
// building (and caching) one if needed.
func (a *App) getOIDCProvider(ctx context.Context) (*oidcProvider, OIDCSettings, error) {
	s := a.oidcSettings()
	if !s.configured() {
		return nil, s, errOIDCNotConfigured
	}
	a.settingsMu.RLock()
	cached := a.oidcProvider
	a.settingsMu.RUnlock()
	if cached != nil && cached.issuer == s.Issuer && cached.clientID == s.ClientID && cached.redirect == s.redirectURL() {
		return cached, s, nil
	}
	built, err := a.buildOIDCProvider(ctx, s)
	if err != nil {
		return nil, s, err
	}
	a.settingsMu.Lock()
	a.oidcProvider = built
	a.settingsMu.Unlock()
	return built, s, nil
}

// oidcStart begins the authorization-code + PKCE flow: it stores state, the PKCE
// verifier, and a nonce in a sealed short-lived cookie, then redirects to the IdP.
func (a *App) oidcStart(w http.ResponseWriter, r *http.Request) {
	if a.sealer == nil {
		a.renderLoginError(w, r, "Single sign-on is unavailable.")
		return
	}
	provider, _, err := a.getOIDCProvider(r.Context())
	if err != nil {
		a.logger.Error("oidc start", "error", err)
		a.renderLoginErrorPage(w, "Single sign-on is unavailable right now.")
		return
	}
	state, _ := auth.RandomToken(24)
	nonce, _ := auth.RandomToken(24)
	verifier := oauth2.GenerateVerifier()
	payload := strings.Join([]string{state, verifier, nonce, strconv.FormatInt(time.Now().Add(oidcStateTTL).Unix(), 10)}, ":")
	sealed, err := a.sealer.Seal(payload)
	if err != nil {
		a.renderLoginErrorPage(w, "Single sign-on is unavailable right now.")
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     oidcStateCookie,
		Value:    sealed,
		Path:     "/",
		MaxAge:   int(oidcStateTTL.Seconds()),
		HttpOnly: true,
		Secure:   a.cfg.CookieSecure,
		SameSite: http.SameSiteLaxMode,
	})
	authURL := provider.config.AuthCodeURL(state, oidc.Nonce(nonce), oauth2.S256ChallengeOption(verifier))
	http.Redirect(w, r, authURL, http.StatusSeeOther)
}

// oidcCallback completes the flow: validate state, exchange the code (with PKCE),
// verify the ID token + nonce, resolve the local user, and establish a session.
func (a *App) oidcCallback(w http.ResponseWriter, r *http.Request) {
	state, verifier, nonce, ok := a.readOIDCState(r)
	a.clearOIDCCookie(w)
	if !ok {
		a.renderLoginErrorPage(w, "Your sign-on attempt expired. Please try again.")
		return
	}
	q := r.URL.Query()
	if errParam := q.Get("error"); errParam != "" {
		a.logger.Warn("oidc callback error", "error", errParam, "description", q.Get("error_description"))
		a.renderLoginErrorPage(w, "Single sign-on was cancelled or denied.")
		return
	}
	if q.Get("state") != state {
		a.renderLoginErrorPage(w, "Single sign-on failed a security check. Please try again.")
		return
	}
	provider, settings, err := a.getOIDCProvider(r.Context())
	if err != nil {
		a.renderLoginErrorPage(w, "Single sign-on is unavailable right now.")
		return
	}
	token, err := provider.config.Exchange(r.Context(), q.Get("code"), oauth2.VerifierOption(verifier))
	if err != nil {
		a.logger.Error("oidc exchange", "error", err)
		a.renderLoginErrorPage(w, "Single sign-on failed. Please try again.")
		return
	}
	rawID, ok := token.Extra("id_token").(string)
	if !ok || rawID == "" {
		a.renderLoginErrorPage(w, "The identity provider did not return an ID token.")
		return
	}
	idToken, err := provider.verifier.Verify(r.Context(), rawID)
	if err != nil {
		a.logger.Error("oidc verify", "error", err)
		a.renderLoginErrorPage(w, "Single sign-on failed to verify your identity.")
		return
	}
	if idToken.Nonce != nonce {
		a.renderLoginErrorPage(w, "Single sign-on failed a security check. Please try again.")
		return
	}
	var claims map[string]any
	if err := idToken.Claims(&claims); err != nil {
		a.renderLoginErrorPage(w, "Single sign-on returned an unreadable identity.")
		return
	}

	user, err := a.resolveOIDCLogin(r.Context(), settings, idToken.Subject, claims)
	if err != nil {
		a.logger.Warn("oidc login rejected", "error", err, "subject", idToken.Subject)
		a.renderLoginErrorPage(w, "No Light IPAM account is linked to that identity.")
		return
	}
	a.auditMeta(r, &user.ID, "auth.login.sso", "user", user.ID, map[string]string{"ip": clientIP(r)})
	a.establishSession(w, r, user.ID)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// resolveOIDCLogin maps an authenticated OIDC identity to a local user: by bound
// subject, then by username (linking the subject), then auto-provisioning a
// viewer when enabled.
func (a *App) resolveOIDCLogin(ctx context.Context, s OIDCSettings, subject string, claims map[string]any) (store.User, error) {
	if subject == "" {
		return store.User{}, errors.New("missing subject")
	}
	if user, err := a.store.FindUserByOIDCSubject(ctx, subject); err == nil {
		return user, nil
	} else if !errors.Is(err, store.ErrNotFound) {
		return store.User{}, err
	}

	username := oidcUsername(claims, s.UsernameClaim)
	if username == "" {
		return store.User{}, errors.New("no username claim")
	}
	if user, err := a.store.FindUserByUsername(ctx, username); err == nil {
		if linkErr := a.store.LinkOIDCSubject(ctx, user.ID, subject); linkErr != nil {
			return store.User{}, linkErr
		}
		return user, nil
	} else if !errors.Is(err, store.ErrNotFound) {
		return store.User{}, err
	}

	if !s.AutoProvision {
		return store.User{}, errors.New("no matching account and auto-provision disabled")
	}
	return a.store.CreateSSOUser(ctx, username, oidcDisplayName(claims, username), store.RoleViewer, subject)
}

// readOIDCState opens the sealed state cookie and returns its parts if unexpired.
func (a *App) readOIDCState(r *http.Request) (state, verifier, nonce string, ok bool) {
	if a.sealer == nil {
		return "", "", "", false
	}
	cookie, err := r.Cookie(oidcStateCookie)
	if err != nil || cookie.Value == "" {
		return "", "", "", false
	}
	payload, err := a.sealer.Open(cookie.Value)
	if err != nil {
		return "", "", "", false
	}
	parts := strings.Split(payload, ":")
	if len(parts) != 4 {
		return "", "", "", false
	}
	expiry, err := strconv.ParseInt(parts[3], 10, 64)
	if err != nil || time.Now().Unix() > expiry {
		return "", "", "", false
	}
	return parts[0], parts[1], parts[2], true
}

func (a *App) clearOIDCCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     oidcStateCookie,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   a.cfg.CookieSecure,
		SameSite: http.SameSiteLaxMode,
	})
}

// renderLoginErrorPage renders the login page with an error and a fresh CSRF
// token (used on OIDC failures that have no submitted form).
func (a *App) renderLoginErrorPage(w http.ResponseWriter, message string) {
	csrf, _ := auth.RandomToken(32)
	a.setCSRFCookie(w, csrf)
	a.renderLoginErrorWithToken(w, message, csrf)
}
