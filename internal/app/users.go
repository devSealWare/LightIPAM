package app

import (
	"errors"
	"net/http"
	"strings"

	"github.com/devSealWare/LightIPAM/internal/auth"
	"github.com/devSealWare/LightIPAM/internal/store"
	"github.com/devSealWare/LightIPAM/internal/ui"
)

// minPasswordLength is the minimum length for any account password, matching
// the admin bootstrap rule.
const minPasswordLength = 12

func (a *App) settingsUsers(w http.ResponseWriter, r *http.Request) {
	session, ok := a.requireAdmin(w, r)
	if !ok {
		return
	}
	a.renderUsersTab(w, r, session, nil, "", usersNotice(r))
}

func (a *App) userCreate(w http.ResponseWriter, r *http.Request) {
	session, ok := a.requireAdmin(w, r)
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
	username := strings.TrimSpace(r.FormValue("username"))
	displayName := strings.TrimSpace(r.FormValue("display_name"))
	password := r.FormValue("password")
	role := strings.TrimSpace(r.FormValue("role"))
	if displayName == "" {
		displayName = username
	}
	form := map[string]string{"username": username, "display_name": displayName, "role": role}
	if username == "" || len(password) < minPasswordLength {
		a.renderUsersTab(w, r, session, form, "Use a username and a password with at least 12 characters.", "")
		return
	}
	if !store.ValidRole(role) {
		a.renderUsersTab(w, r, session, form, "Choose a valid role.", "")
		return
	}
	hash, err := auth.HashPassword(password)
	if err != nil {
		http.Error(w, "Unable to secure password", http.StatusInternalServerError)
		return
	}
	user, err := a.store.CreateUser(r.Context(), username, displayName, hash, role)
	if err != nil {
		a.renderUsersTab(w, r, session, form, "Unable to create the user. The username may already be taken.", "")
		return
	}
	a.auditMeta(r, &session.User.ID, "user.created", "user", user.ID, map[string]string{"username": user.Username, "role": user.Role})
	http.Redirect(w, r, "/settings/users?notice=created", http.StatusSeeOther)
}

func (a *App) userSetRole(w http.ResponseWriter, r *http.Request) {
	session, target, ok := a.loadManagedUser(w, r)
	if !ok {
		return
	}
	if !a.verifySessionCSRF(r, session) {
		http.Error(w, "Invalid form token", http.StatusForbidden)
		return
	}
	role := strings.TrimSpace(r.FormValue("role"))
	if !store.ValidRole(role) {
		a.renderUsersTab(w, r, session, nil, "Choose a valid role.", "")
		return
	}
	// Guard against removing the last admin: demoting the only admin would lock
	// everyone out of user and settings management.
	if target.IsAdmin && role != store.RoleAdmin {
		if last, err := a.isLastAdmin(r, target.ID); err != nil {
			http.Error(w, "Unable to update role", http.StatusInternalServerError)
			return
		} else if last {
			a.renderUsersTab(w, r, session, nil, "You cannot remove the last admin. Promote another user first.", "")
			return
		}
	}
	if err := a.store.SetUserRole(r.Context(), target.ID, role); err != nil {
		a.logger.Error("set user role", "error", err)
		http.Error(w, "Unable to update role", http.StatusInternalServerError)
		return
	}
	a.auditMeta(r, &session.User.ID, "user.role.updated", "user", target.ID, map[string]string{"username": target.Username, "role": role})
	http.Redirect(w, r, "/settings/users?notice=updated", http.StatusSeeOther)
}

func (a *App) userResetPassword(w http.ResponseWriter, r *http.Request) {
	session, target, ok := a.loadManagedUser(w, r)
	if !ok {
		return
	}
	if !a.verifySessionCSRF(r, session) {
		http.Error(w, "Invalid form token", http.StatusForbidden)
		return
	}
	password := r.FormValue("password")
	if len(password) < minPasswordLength {
		a.renderUsersTab(w, r, session, nil, "New password must be at least 12 characters.", "")
		return
	}
	hash, err := auth.HashPassword(password)
	if err != nil {
		http.Error(w, "Unable to secure password", http.StatusInternalServerError)
		return
	}
	if err := a.store.SetUserPassword(r.Context(), target.ID, hash); err != nil {
		a.logger.Error("reset user password", "error", err)
		http.Error(w, "Unable to reset password", http.StatusInternalServerError)
		return
	}
	// Revoke the target's sessions so the new password takes effect everywhere.
	if _, err := a.store.DeleteUserSessions(r.Context(), target.ID); err != nil {
		a.logger.Error("revoke sessions after reset", "error", err)
	}
	a.auditMeta(r, &session.User.ID, "user.password.reset", "user", target.ID, map[string]string{"username": target.Username})
	http.Redirect(w, r, "/settings/users?notice=password", http.StatusSeeOther)
}

func (a *App) userDeleteConfirm(w http.ResponseWriter, r *http.Request) {
	session, target, ok := a.loadManagedUser(w, r)
	if !ok {
		return
	}
	_ = ui.Render(w, "confirm.html", ui.PageData{
		Title:     "Delete User",
		User:      session.User,
		CSRF:      session.CSRFToken,
		ActiveNav: "settings",
		Form: map[string]string{
			"heading":      "Delete user",
			"message":      "This permanently deletes the account and signs out its sessions.",
			"subject":      target.Username,
			"action":       "/settings/users/" + target.ID + "/delete",
			"cancel":       "/settings/users",
			"confirm_text": "Delete user",
		},
	})
}

func (a *App) userDelete(w http.ResponseWriter, r *http.Request) {
	session, target, ok := a.loadManagedUser(w, r)
	if !ok {
		return
	}
	if !a.verifySessionCSRF(r, session) {
		http.Error(w, "Invalid form token", http.StatusForbidden)
		return
	}
	if target.ID == session.User.ID {
		a.renderUsersTab(w, r, session, nil, "You cannot delete your own account.", "")
		return
	}
	if target.IsAdmin {
		if last, err := a.isLastAdmin(r, target.ID); err != nil {
			http.Error(w, "Unable to delete user", http.StatusInternalServerError)
			return
		} else if last {
			a.renderUsersTab(w, r, session, nil, "You cannot delete the last admin.", "")
			return
		}
	}
	if err := a.store.DeleteUser(r.Context(), target.ID); err != nil {
		a.logger.Error("delete user", "error", err)
		http.Error(w, "Unable to delete user", http.StatusInternalServerError)
		return
	}
	a.auditMeta(r, &session.User.ID, "user.deleted", "user", target.ID, map[string]string{"username": target.Username})
	http.Redirect(w, r, "/settings/users?notice=deleted", http.StatusSeeOther)
}

// loadManagedUser resolves the admin session and the target user the request
// addresses, 404ing an unknown id.
func (a *App) loadManagedUser(w http.ResponseWriter, r *http.Request) (store.Session, store.User, bool) {
	session, ok := a.requireAdmin(w, r)
	if !ok {
		return store.Session{}, store.User{}, false
	}
	target, err := a.store.GetUser(r.Context(), r.PathValue("id"))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			http.NotFound(w, r)
			return store.Session{}, store.User{}, false
		}
		a.logger.Error("get user", "error", err)
		http.Error(w, "Unable to load user", http.StatusInternalServerError)
		return store.Session{}, store.User{}, false
	}
	return session, target, true
}

// isLastAdmin reports whether the given admin user is the only admin left.
func (a *App) isLastAdmin(r *http.Request, userID string) (bool, error) {
	count, err := a.store.CountAdmins(r.Context())
	if err != nil {
		a.logger.Error("count admins", "error", err)
		return false, err
	}
	return count <= 1, nil
}

// renderUsersTab renders the Settings page on its Users tab.
func (a *App) renderUsersTab(w http.ResponseWriter, r *http.Request, session store.Session, form map[string]string, errMsg, notice string) {
	users, err := a.store.ListUsers(r.Context())
	if err != nil {
		a.logger.Error("list users", "error", err)
		http.Error(w, "Unable to load users", http.StatusInternalServerError)
		return
	}
	if form == nil {
		form = map[string]string{"role": store.RoleViewer}
	}
	_ = ui.Render(w, "settings.html", ui.PageData{
		Title:            "Settings",
		User:             session.User,
		CSRF:             session.CSRFToken,
		Error:            errMsg,
		SuccessMessage:   notice,
		Users:            users,
		CurrentSessionID: session.ID,
		Form:             form,
		ActiveNav:        "settings",
		ActiveTab:        "users",
	})
}

// usersNotice maps the post-redirect ?notice marker to a banner message.
func usersNotice(r *http.Request) string {
	switch r.URL.Query().Get("notice") {
	case "created":
		return "User created."
	case "updated":
		return "Role updated."
	case "password":
		return "Password reset; the user's sessions were signed out."
	case "deleted":
		return "User deleted."
	default:
		return ""
	}
}
