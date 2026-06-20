package app

import (
	"net/http"

	"github.com/devSealWare/LightIPAM/internal/store"
	"github.com/devSealWare/LightIPAM/internal/ui"
)

func (a *App) settingsBackup(w http.ResponseWriter, r *http.Request) {
	session, ok := a.requireAdmin(w, r)
	if !ok {
		return
	}
	a.renderBackupTab(w, r, session, "", backupNotice(r))
}

func (a *App) backupCreate(w http.ResponseWriter, r *http.Request) {
	session, ok := a.requireAdmin(w, r)
	if !ok {
		return
	}
	if !a.verifySessionCSRF(r, session) {
		http.Error(w, "Invalid form token", http.StatusForbidden)
		return
	}
	if !a.backups.Enabled() {
		a.renderBackupTab(w, r, session, "Backups are not configured (set BACKUP_DIR).", "")
		return
	}
	migration, err := a.store.MigrationVersion(r.Context())
	if err != nil {
		a.logger.Error("backup migration version", "error", err)
	}
	b, err := a.backups.Create(r.Context(), migration)
	if err != nil {
		a.logger.Error("create backup", "error", err)
		a.renderBackupTab(w, r, session, "Backup failed. Check that pg_dump is available and the directory is writable.", "")
		return
	}
	a.auditMeta(r, &session.User.ID, "backup.created", "backup", b.Name, map[string]string{
		"migration": intString(b.Migration),
	})
	http.Redirect(w, r, "/settings/backup?notice=created", http.StatusSeeOther)
}

func (a *App) backupDownload(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.requireAdmin(w, r); !ok {
		return
	}
	path, err := a.backups.Path(r.PathValue("name"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", "attachment; filename=\""+r.PathValue("name")+"\"")
	http.ServeFile(w, r, path)
}

func (a *App) backupDelete(w http.ResponseWriter, r *http.Request) {
	session, ok := a.requireAdmin(w, r)
	if !ok {
		return
	}
	if !a.verifySessionCSRF(r, session) {
		http.Error(w, "Invalid form token", http.StatusForbidden)
		return
	}
	name := r.PathValue("name")
	if err := a.backups.Delete(name); err != nil {
		a.logger.Error("delete backup", "error", err)
		a.renderBackupTab(w, r, session, "Unable to delete that backup.", "")
		return
	}
	a.audit(r, &session.User.ID, "backup.deleted", "backup", name)
	http.Redirect(w, r, "/settings/backup?notice=deleted", http.StatusSeeOther)
}

// renderBackupTab renders the Settings page on its Backup & Restore tab.
func (a *App) renderBackupTab(w http.ResponseWriter, r *http.Request, session store.Session, errMsg, notice string) {
	list, err := a.backups.List()
	if err != nil && a.backups.Enabled() {
		a.logger.Error("list backups", "error", err)
	}
	_ = ui.Render(w, "settings.html", ui.PageData{
		Title:          "Settings",
		User:           session.User,
		CSRF:           session.CSRFToken,
		Error:          errMsg,
		SuccessMessage: notice,
		Backups:        list,
		BackupDir:      a.backups.Dir(),
		BackupEnabled:  a.backups.Enabled(),
		BackupWritable: a.backups.Writable(),
		ActiveNav:      "settings",
		ActiveTab:      "backup",
	})
}

// backupNotice maps the post-redirect ?notice marker to a banner message.
func backupNotice(r *http.Request) string {
	switch r.URL.Query().Get("notice") {
	case "created":
		return "Backup created."
	case "deleted":
		return "Backup deleted."
	default:
		return ""
	}
}
