package app

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/devSealWare/LightIPAM/internal/scanner/pki"
	"github.com/devSealWare/LightIPAM/internal/store"
	"github.com/devSealWare/LightIPAM/internal/ui"
)

// ensureCA loads the managed CA from the DB (unsealing its key) or generates and
// persists a new one on first boot. Without a sealer the managed CA is disabled
// (the dev CA remains usable).
func (a *App) ensureCA(ctx context.Context) {
	if a.sealer == nil {
		a.logger.Warn("managed CA disabled: no encryption key configured")
		return
	}
	if certPEM, sealedKey, err := a.store.GetAppCA(ctx); err == nil {
		keyPEM, oerr := a.sealer.Open(sealedKey)
		if oerr == nil {
			if ca, lerr := pki.LoadCA([]byte(certPEM), []byte(keyPEM)); lerr == nil {
				a.setCA(ca)
				return
			} else {
				a.logger.Error("load managed CA", "error", lerr)
			}
		} else {
			a.logger.Error("unseal managed CA key", "error", oerr)
		}
	} else if !errors.Is(err, store.ErrNotFound) {
		a.logger.Error("get managed CA", "error", err)
		return
	}
	a.generateAndStoreCA(ctx)
}

func (a *App) generateAndStoreCA(ctx context.Context) {
	ca, err := pki.NewCA(0)
	if err != nil {
		a.logger.Error("generate managed CA", "error", err)
		return
	}
	keyPEM, err := ca.KeyPEM()
	if err != nil {
		a.logger.Error("encode managed CA key", "error", err)
		return
	}
	sealed, err := a.sealer.Seal(string(keyPEM))
	if err != nil {
		a.logger.Error("seal managed CA key", "error", err)
		return
	}
	if err := a.store.SaveAppCA(ctx, string(ca.CertPEM()), sealed); err != nil {
		a.logger.Error("save managed CA", "error", err)
		return
	}
	a.setCA(ca)
	a.logger.Info("generated managed agent-certificate CA", "fingerprint", ca.Fingerprint())
}

func (a *App) currentCA() *pki.CA {
	a.caMu.RLock()
	defer a.caMu.RUnlock()
	return a.ca
}

func (a *App) setCA(ca *pki.CA) {
	a.caMu.Lock()
	defer a.caMu.Unlock()
	a.ca = ca
}

func (a *App) settingsCertificates(w http.ResponseWriter, r *http.Request) {
	session, ok := a.requireAdmin(w, r)
	if !ok {
		return
	}
	a.renderCertsTab(w, session, "", certsNotice(r))
}

// certIssueAgent issues a short-lived agent server certificate bundle and streams
// it as a zip (ca.crt + agent.crt + agent.key).
func (a *App) certIssueAgent(w http.ResponseWriter, r *http.Request) {
	session, ok := a.requireAdmin(w, r)
	if !ok {
		return
	}
	if !a.verifySessionCSRF(r, session) {
		http.Error(w, "Invalid form token", http.StatusForbidden)
		return
	}
	ca := a.currentCA()
	if ca == nil {
		a.renderCertsTab(w, session, "The managed CA is unavailable.", "")
		return
	}
	cn := strings.TrimSpace(r.FormValue("cn"))
	if cn == "" {
		cn = pki.AgentServerCN
	}
	dnsNames := splitListField(r.FormValue("dns_names"))
	if len(dnsNames) == 0 {
		dnsNames = []string{pki.AgentServerCN, "scanner-agent", "localhost"}
	}
	ips := []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback}
	for _, raw := range splitListField(r.FormValue("ips")) {
		if ip := net.ParseIP(raw); ip != nil {
			ips = append(ips, ip)
		}
	}
	ttl := certTTL(r.FormValue("ttl_days"), pki.DefaultLeafValidFor)
	certPEM, keyPEM, err := ca.IssueServer(cn, dnsNames, ips, ttl)
	if err != nil {
		a.logger.Error("issue agent cert", "error", err)
		a.renderCertsTab(w, session, "Unable to issue the certificate.", "")
		return
	}
	a.auditMeta(r, &session.User.ID, "agent.cert.issued", "scan_agent", cn, map[string]string{"cn": cn})
	a.streamCertZip(w, "lightipam-agent-certs.zip", map[string][]byte{
		"ca.crt":    ca.CertPEM(),
		"agent.crt": certPEM,
		"agent.key": keyPEM,
	})
}

// certIssueApp issues the app's own client certificate bundle.
func (a *App) certIssueApp(w http.ResponseWriter, r *http.Request) {
	session, ok := a.requireAdmin(w, r)
	if !ok {
		return
	}
	if !a.verifySessionCSRF(r, session) {
		http.Error(w, "Invalid form token", http.StatusForbidden)
		return
	}
	ca := a.currentCA()
	if ca == nil {
		a.renderCertsTab(w, session, "The managed CA is unavailable.", "")
		return
	}
	ttl := certTTL(r.FormValue("ttl_days"), pki.DefaultLeafValidFor)
	certPEM, keyPEM, err := ca.IssueClient(pki.AppClientCN, ttl)
	if err != nil {
		a.logger.Error("issue app cert", "error", err)
		a.renderCertsTab(w, session, "Unable to issue the certificate.", "")
		return
	}
	a.audit(r, &session.User.ID, "app.cert.issued", "app", pki.AppClientCN)
	a.streamCertZip(w, "lightipam-app-certs.zip", map[string][]byte{
		"ca.crt":  ca.CertPEM(),
		"app.crt": certPEM,
		"app.key": keyPEM,
	})
}

// certDownloadCA serves the managed CA certificate (public) for trust distribution.
func (a *App) certDownloadCA(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.requireAdmin(w, r); !ok {
		return
	}
	ca := a.currentCA()
	if ca == nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", "attachment; filename=\"ca.crt\"")
	_, _ = w.Write(ca.CertPEM())
}

// certRotateCA generates a brand-new CA. This invalidates every previously issued
// agent/app certificate, so all peers must be re-issued and redeployed.
func (a *App) certRotateCA(w http.ResponseWriter, r *http.Request) {
	session, ok := a.requireAdmin(w, r)
	if !ok {
		return
	}
	if !a.verifySessionCSRF(r, session) {
		http.Error(w, "Invalid form token", http.StatusForbidden)
		return
	}
	a.generateAndStoreCA(r.Context())
	if a.currentCA() == nil {
		a.renderCertsTab(w, session, "Unable to rotate the CA.", "")
		return
	}
	a.audit(r, &session.User.ID, "agent.ca.rotated", "app", "managed-ca")
	http.Redirect(w, r, "/settings/certificates?notice=rotated", http.StatusSeeOther)
}

func (a *App) streamCertZip(w http.ResponseWriter, filename string, files map[string][]byte) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, data := range files {
		f, err := zw.Create(name)
		if err == nil {
			_, _ = f.Write(data)
		}
	}
	if err := zw.Close(); err != nil {
		http.Error(w, "Unable to build bundle", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", "attachment; filename=\""+filename+"\"")
	_, _ = w.Write(buf.Bytes())
}

func (a *App) renderCertsTab(w http.ResponseWriter, session store.Session, errMsg, notice string) {
	data := ui.PageData{
		Title:          "Settings",
		User:           session.User,
		CSRF:           session.CSRFToken,
		Error:          errMsg,
		SuccessMessage: notice,
		ActiveNav:      "settings",
		ActiveTab:      "certificates",
	}
	if ca := a.currentCA(); ca != nil {
		data.CAFingerprint = ca.Fingerprint()
		data.CAExpiry = ca.NotAfter()
		data.CAReady = true
	}
	data.LeafDefaultDays = int(pki.DefaultLeafValidFor / (24 * time.Hour))
	_ = ui.Render(w, "settings.html", data)
}

func certsNotice(r *http.Request) string {
	if r.URL.Query().Get("notice") == "rotated" {
		return "Generated a new CA. Re-issue and redeploy agent and app certificates."
	}
	return ""
}

// splitListField splits a comma/space/newline-separated text field into trimmed
// non-empty values.
func splitListField(value string) []string {
	fields := strings.FieldsFunc(value, func(r rune) bool {
		return r == ',' || r == '\n' || r == ' ' || r == '\t' || r == '\r'
	})
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, f)
		}
	}
	return out
}

// certTTL parses a day count into a duration, clamped to [1, 825] days.
func certTTL(daysField string, fallback time.Duration) time.Duration {
	n, err := strconv.Atoi(strings.TrimSpace(daysField))
	if err != nil || n < 1 || n > 825 {
		return fallback
	}
	return time.Duration(n) * 24 * time.Hour
}
