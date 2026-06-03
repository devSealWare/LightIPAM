package app

import (
	"errors"
	"net/http"
	"net/url"

	"github.com/devSealWare/LightIPAM/internal/store"
	"github.com/devSealWare/LightIPAM/internal/ui"
)

func (a *App) discoveriesIndex(w http.ResponseWriter, r *http.Request) {
	session, ok := a.requireSession(w, r)
	if !ok {
		return
	}
	status := r.URL.Query().Get("status")
	discoveries, err := a.store.ListDiscoveries(r.Context(), status, 200)
	if err != nil {
		a.logger.Error("list discoveries", "error", err)
		http.Error(w, "Unable to load discoveries", http.StatusInternalServerError)
		return
	}
	pending, err := a.store.CountPendingDiscoveries(r.Context())
	if err != nil {
		a.logger.Error("count pending discoveries", "error", err)
	}
	_ = ui.Render(w, "discoveries.html", ui.PageData{
		Title:            "Discoveries",
		User:             session.User,
		CSRF:             session.CSRFToken,
		Discoveries:      discoveries,
		PendingDiscovery: pending,
		Error:            r.URL.Query().Get("error"),
		Form:             map[string]string{"status": status},
		ActiveNav:        "discoveries",
	})
}

func (a *App) discoveryImport(w http.ResponseWriter, r *http.Request) {
	session, ok := a.requireSession(w, r)
	if !ok {
		return
	}
	if !a.verifySessionCSRF(r, session) {
		http.Error(w, "Invalid form token", http.StatusForbidden)
		return
	}
	id := r.PathValue("id")
	discovery, err := a.store.ImportDiscovery(r.Context(), id)
	if err != nil {
		if errors.Is(err, store.ErrNoContainingSubnet) {
			http.Redirect(w, r, "/discoveries?error="+url.QueryEscape("No managed subnet contains that address — create the subnet first, then import."), http.StatusSeeOther)
			return
		}
		if errors.Is(err, store.ErrNotFound) {
			http.NotFound(w, r)
			return
		}
		a.logger.Error("import discovery", "error", err)
		http.Error(w, "Unable to import discovery", http.StatusInternalServerError)
		return
	}
	a.audit(r, &session.User.ID, "scan.discovery.imported", "ip_address", discovery.ImportedAddressID)
	http.Redirect(w, r, "/discoveries", http.StatusSeeOther)
}

func (a *App) discoveryDismiss(w http.ResponseWriter, r *http.Request) {
	session, ok := a.requireSession(w, r)
	if !ok {
		return
	}
	if !a.verifySessionCSRF(r, session) {
		http.Error(w, "Invalid form token", http.StatusForbidden)
		return
	}
	id := r.PathValue("id")
	if err := a.store.DismissDiscovery(r.Context(), id); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			http.NotFound(w, r)
			return
		}
		a.logger.Error("dismiss discovery", "error", err)
		http.Error(w, "Unable to dismiss discovery", http.StatusInternalServerError)
		return
	}
	a.audit(r, &session.User.ID, "scan.discovery.dismissed", "scan_discovery", id)
	http.Redirect(w, r, "/discoveries", http.StatusSeeOther)
}
