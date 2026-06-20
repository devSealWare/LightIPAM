package app

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/devSealWare/LightIPAM/internal/auth"
	"github.com/devSealWare/LightIPAM/internal/store"
	"github.com/devSealWare/LightIPAM/internal/ui"
	qrcode "github.com/skip2/go-qrcode"
)

const (
	mfaCookie       = "lightipam_mfa"
	mfaChallengeTTL = 5 * time.Minute
	totpIssuer      = "Light IPAM"
	recoveryCodeQty = 10
)

// startMFAChallenge seals a short-lived pending-MFA token (user id + expiry) into
// a cookie and primes the CSRF cookie for the challenge form. Returns false when
// the secret could not be sealed (no sealer), so the caller can fail safe.
func (a *App) startMFAChallenge(w http.ResponseWriter, r *http.Request, userID string) bool {
	if a.sealer == nil {
		return false
	}
	payload := fmt.Sprintf("%s:%d", userID, time.Now().Add(mfaChallengeTTL).Unix())
	token, err := a.sealer.Seal(payload)
	if err != nil {
		a.logger.Error("seal mfa challenge", "error", err)
		return false
	}
	http.SetCookie(w, &http.Cookie{
		Name:     mfaCookie,
		Value:    token,
		Path:     "/",
		MaxAge:   int(mfaChallengeTTL.Seconds()),
		HttpOnly: true,
		Secure:   a.cfg.CookieSecure,
		SameSite: http.SameSiteLaxMode,
	})
	csrf, _ := auth.RandomToken(32)
	a.setCSRFCookie(w, csrf)
	return true
}

// pendingMFAUser opens the pending-MFA cookie and returns the user id if it is
// present and unexpired.
func (a *App) pendingMFAUser(r *http.Request) (string, bool) {
	if a.sealer == nil {
		return "", false
	}
	cookie, err := r.Cookie(mfaCookie)
	if err != nil || cookie.Value == "" {
		return "", false
	}
	payload, err := a.sealer.Open(cookie.Value)
	if err != nil {
		return "", false
	}
	userID, expiry, ok := strings.Cut(payload, ":")
	if !ok {
		return "", false
	}
	unix, err := strconv.ParseInt(expiry, 10, 64)
	if err != nil || time.Now().Unix() > unix {
		return "", false
	}
	return userID, true
}

func (a *App) clearMFACookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     mfaCookie,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   a.cfg.CookieSecure,
		SameSite: http.SameSiteLaxMode,
	})
}

func (a *App) mfaChallengeForm(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.pendingMFAUser(r); !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	csrf, err := auth.RandomToken(32)
	if err != nil {
		http.Error(w, "Unable to create form token", http.StatusInternalServerError)
		return
	}
	a.setCSRFCookie(w, csrf)
	_ = ui.Render(w, "mfa_challenge.html", ui.PageData{Title: "Two-factor verification", CSRF: csrf})
}

func (a *App) mfaChallengeSubmit(w http.ResponseWriter, r *http.Request) {
	if !a.verifyFormCSRF(r) {
		http.Error(w, "Invalid form token", http.StatusForbidden)
		return
	}
	userID, ok := a.pendingMFAUser(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form", http.StatusBadRequest)
		return
	}
	code := strings.TrimSpace(r.FormValue("code"))
	enrollment, err := a.store.GetUserTOTP(r.Context(), userID)
	if err != nil || !enrollment.Enabled {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	secretValue, err := a.sealer.Open(enrollment.Secret)
	if err != nil {
		a.logger.Error("open totp secret", "error", err)
		a.renderMFAChallengeError(w, r, "Unable to verify the code. Please try again.")
		return
	}

	verified := auth.VerifyTOTP(secretValue, code, time.Now())
	usedRecovery := false
	if !verified {
		// Fall back to a single-use recovery code.
		if ok, rerr := a.store.ConsumeRecoveryCode(r.Context(), userID, auth.HashRecoveryCode(code)); rerr != nil {
			a.logger.Error("consume recovery code", "error", rerr)
		} else if ok {
			verified, usedRecovery = true, true
		}
	}
	if !verified {
		a.auditMeta(r, &userID, "auth.mfa.failed", "user", userID, map[string]string{"ip": clientIP(r)})
		a.renderMFAChallengeError(w, r, "That code is incorrect or expired.")
		return
	}

	a.clearMFACookie(w)
	action := "auth.mfa.success"
	if usedRecovery {
		action = "auth.mfa.recovery_used"
	}
	if err := a.store.CreateAuditLog(r.Context(), &userID, action, "user", userID, "{}"); err != nil {
		a.logger.Error("create audit log", "error", err)
	}
	a.establishSession(w, r, userID)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (a *App) renderMFAChallengeError(w http.ResponseWriter, r *http.Request, message string) {
	_ = ui.Render(w, "mfa_challenge.html", ui.PageData{
		Title: "Two-factor verification",
		Error: message,
		CSRF:  r.FormValue("csrf_token"),
	})
}

// mfaSettings renders the MFA enrollment/management view on the account area.
// While disabled it ensures a pending secret exists so the QR/manual key and the
// confirm form have something to show.
func (a *App) mfaSettings(w http.ResponseWriter, r *http.Request) {
	session, ok := a.requireSession(w, r)
	if !ok {
		return
	}
	if a.sealer == nil {
		http.Error(w, "Two-factor is unavailable: no encryption key configured.", http.StatusServiceUnavailable)
		return
	}
	enrollment, err := a.store.GetUserTOTP(r.Context(), session.User.ID)
	enabled := err == nil && enrollment.Enabled
	data := ui.PageData{
		Title:      "Two-factor authentication",
		User:       session.User,
		CSRF:       session.CSRFToken,
		ActiveNav:  "account",
		MFAEnabled: enabled,
	}
	if enabled {
		remaining, _ := a.store.CountUnusedRecoveryCodes(r.Context(), session.User.ID)
		data.RecoveryRemaining = remaining
		_ = ui.Render(w, "mfa_settings.html", data)
		return
	}

	// Not enabled: (re)issue a pending secret unless one already exists, so a page
	// refresh keeps the same QR.
	var secretValue string
	if err == nil && enrollment.Secret != "" {
		if secretValue, err = a.sealer.Open(enrollment.Secret); err != nil {
			secretValue = ""
		}
	}
	if secretValue == "" {
		secretValue, err = auth.GenerateTOTPSecret()
		if err != nil {
			http.Error(w, "Unable to start enrollment", http.StatusInternalServerError)
			return
		}
		sealed, serr := a.sealer.Seal(secretValue)
		if serr != nil {
			http.Error(w, "Unable to start enrollment", http.StatusInternalServerError)
			return
		}
		if serr := a.store.StartTOTPEnrollment(r.Context(), session.User.ID, sealed); serr != nil {
			a.logger.Error("start totp enrollment", "error", serr)
			http.Error(w, "Unable to start enrollment", http.StatusInternalServerError)
			return
		}
	}
	data.TOTPSecretFormatted = auth.FormatTOTPSecret(secretValue)
	data.TOTPURI = auth.TOTPProvisioningURI(secretValue, session.User.Username, totpIssuer)
	_ = ui.Render(w, "mfa_settings.html", data)
}

// mfaQR renders the pending enrollment's provisioning URI as a QR PNG. It only
// serves while MFA is not yet enabled (the secret should never be re-displayed
// afterwards).
func (a *App) mfaQR(w http.ResponseWriter, r *http.Request) {
	session, ok := a.requireSession(w, r)
	if !ok {
		return
	}
	if a.sealer == nil {
		http.NotFound(w, r)
		return
	}
	enrollment, err := a.store.GetUserTOTP(r.Context(), session.User.ID)
	if err != nil || enrollment.Enabled {
		http.NotFound(w, r)
		return
	}
	secretValue, err := a.sealer.Open(enrollment.Secret)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	uri := auth.TOTPProvisioningURI(secretValue, session.User.Username, totpIssuer)
	png, err := qrcode.Encode(uri, qrcode.Medium, 256)
	if err != nil {
		http.Error(w, "Unable to render QR", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(png)
}

func (a *App) mfaEnable(w http.ResponseWriter, r *http.Request) {
	session, ok := a.requireSession(w, r)
	if !ok {
		return
	}
	if !a.verifySessionCSRF(r, session) {
		http.Error(w, "Invalid form token", http.StatusForbidden)
		return
	}
	if a.sealer == nil {
		http.Error(w, "Two-factor is unavailable", http.StatusServiceUnavailable)
		return
	}
	enrollment, err := a.store.GetUserTOTP(r.Context(), session.User.ID)
	if err != nil || enrollment.Enabled {
		http.Redirect(w, r, "/account/mfa", http.StatusSeeOther)
		return
	}
	secretValue, err := a.sealer.Open(enrollment.Secret)
	if err != nil {
		http.Error(w, "Unable to verify enrollment", http.StatusInternalServerError)
		return
	}
	code := strings.TrimSpace(r.FormValue("code"))
	if !auth.VerifyTOTP(secretValue, code, time.Now()) {
		a.renderMFAEnrollError(w, r, session, secretValue, "That code didn't match. Make sure your device clock is correct and try again.")
		return
	}
	codes, err := auth.GenerateRecoveryCodes(recoveryCodeQty)
	if err != nil {
		http.Error(w, "Unable to generate recovery codes", http.StatusInternalServerError)
		return
	}
	hashes := make([]string, len(codes))
	for i, c := range codes {
		hashes[i] = auth.HashRecoveryCode(c)
	}
	if err := a.store.EnableTOTP(r.Context(), session.User.ID, hashes); err != nil {
		a.logger.Error("enable totp", "error", err)
		http.Error(w, "Unable to enable two-factor", http.StatusInternalServerError)
		return
	}
	a.audit(r, &session.User.ID, "auth.mfa.enabled", "user", session.User.ID)
	_ = ui.Render(w, "mfa_settings.html", ui.PageData{
		Title:             "Two-factor authentication",
		User:              session.User,
		CSRF:              session.CSRFToken,
		ActiveNav:         "account",
		MFAEnabled:        true,
		RecoveryCodes:     codes,
		RecoveryRemaining: len(codes),
		SuccessMessage:    "Two-factor authentication is on. Save your recovery codes now — they are shown only once.",
	})
}

func (a *App) renderMFAEnrollError(w http.ResponseWriter, r *http.Request, session store.Session, secretValue, message string) {
	_ = ui.Render(w, "mfa_settings.html", ui.PageData{
		Title:               "Two-factor authentication",
		User:                session.User,
		CSRF:                session.CSRFToken,
		ActiveNav:           "account",
		Error:               message,
		TOTPSecretFormatted: auth.FormatTOTPSecret(secretValue),
		TOTPURI:             auth.TOTPProvisioningURI(secretValue, session.User.Username, totpIssuer),
	})
}

func (a *App) mfaDisable(w http.ResponseWriter, r *http.Request) {
	session, ok := a.requireSession(w, r)
	if !ok {
		return
	}
	if !a.verifySessionCSRF(r, session) {
		http.Error(w, "Invalid form token", http.StatusForbidden)
		return
	}
	// Require a valid current code (or recovery code) to turn the factor off, so a
	// walk-up on an unlocked session cannot silently remove MFA.
	enrollment, err := a.store.GetUserTOTP(r.Context(), session.User.ID)
	if err != nil || !enrollment.Enabled {
		http.Redirect(w, r, "/account/mfa", http.StatusSeeOther)
		return
	}
	code := strings.TrimSpace(r.FormValue("code"))
	secretValue, _ := a.sealer.Open(enrollment.Secret)
	verified := secretValue != "" && auth.VerifyTOTP(secretValue, code, time.Now())
	if !verified {
		if ok, _ := a.store.ConsumeRecoveryCode(r.Context(), session.User.ID, auth.HashRecoveryCode(code)); ok {
			verified = true
		}
	}
	if !verified {
		a.renderAccount(w, r, session, "Enter a current code to turn off two-factor.", "")
		return
	}
	if err := a.store.DisableTOTP(r.Context(), session.User.ID); err != nil {
		a.logger.Error("disable totp", "error", err)
		http.Error(w, "Unable to disable two-factor", http.StatusInternalServerError)
		return
	}
	a.audit(r, &session.User.ID, "auth.mfa.disabled", "user", session.User.ID)
	http.Redirect(w, r, "/account?notice=mfa_off", http.StatusSeeOther)
}
