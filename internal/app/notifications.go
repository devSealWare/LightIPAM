package app

import (
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/devSealWare/LightIPAM/internal/store"
	"github.com/devSealWare/LightIPAM/internal/ui"
	"github.com/devSealWare/LightIPAM/internal/webhook"
)

// --- Notifications (change webhooks) settings tab, ADR 0022 ---

func (a *App) settingsNotifications(w http.ResponseWriter, r *http.Request) {
	session, ok := a.requireAdmin(w, r)
	if !ok {
		return
	}
	a.renderNotificationsTab(w, r, session, nil, "", notificationsNotice(r))
}

func (a *App) renderNotificationsTab(w http.ResponseWriter, r *http.Request, session store.Session, form map[string]string, errMsg, notice string) {
	hooks, err := a.store.ListWebhooks(r.Context())
	if err != nil {
		a.logger.Error("list webhooks", "error", err)
		http.Error(w, "Unable to load webhooks", http.StatusInternalServerError)
		return
	}
	deliveries, err := a.store.ListWebhookDeliveries(r.Context(), 25)
	if err != nil {
		a.logger.Error("list webhook deliveries", "error", err)
	}
	if form == nil {
		form = map[string]string{"enabled": "on"}
	}
	_ = ui.Render(w, "settings.html", ui.PageData{
		Title:             "Settings",
		User:              session.User,
		CSRF:              session.CSRFToken,
		Error:             errMsg,
		SuccessMessage:    notice,
		Webhooks:          hooks,
		WebhookDeliveries: deliveries,
		WebhookCategories: webhook.Categories(),
		Form:              form,
		ActiveNav:         "settings",
		ActiveTab:         "notifications",
	})
}

func (a *App) webhookCreate(w http.ResponseWriter, r *http.Request) {
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
	input, rawSecret, err := parseWebhookForm(r.PostForm)
	if err != nil {
		a.renderNotificationsTab(w, r, session, submittedWebhookForm(r.PostForm), err.Error(), "")
		return
	}
	sealed := a.sealWebhookSecret(rawSecret)
	input.SecretSealed = &sealed
	wh, err := a.store.CreateWebhook(r.Context(), input)
	if err != nil {
		a.logger.Error("create webhook", "error", err)
		a.renderNotificationsTab(w, r, session, submittedWebhookForm(r.PostForm), "Unable to create webhook.", "")
		return
	}
	a.audit(r, &session.User.ID, "settings.notifications.created", "webhook", wh.ID)
	a.webhooks.Refresh(r.Context())
	http.Redirect(w, r, "/settings/notifications?notice=created", http.StatusSeeOther)
}

func (a *App) webhookUpdate(w http.ResponseWriter, r *http.Request) {
	session, wh, ok := a.loadWebhookPage(w, r)
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
	input, rawSecret, err := parseWebhookForm(r.PostForm)
	if err != nil {
		a.renderNotificationsTab(w, r, session, nil, err.Error(), "")
		return
	}
	// A blank secret field keeps the stored secret; a non-blank one replaces it.
	if rawSecret != "" {
		sealed := a.sealWebhookSecret(rawSecret)
		input.SecretSealed = &sealed
	}
	if _, err := a.store.UpdateWebhook(r.Context(), wh.ID, input); err != nil {
		a.logger.Error("update webhook", "error", err)
		a.renderNotificationsTab(w, r, session, nil, "Unable to update webhook.", "")
		return
	}
	a.audit(r, &session.User.ID, "settings.notifications.updated", "webhook", wh.ID)
	a.webhooks.Refresh(r.Context())
	http.Redirect(w, r, "/settings/notifications?notice=updated", http.StatusSeeOther)
}

func (a *App) webhookTest(w http.ResponseWriter, r *http.Request) {
	session, wh, ok := a.loadWebhookPage(w, r)
	if !ok {
		return
	}
	if !a.verifySessionCSRF(r, session) {
		http.Error(w, "Invalid form token", http.StatusForbidden)
		return
	}
	result, err := a.webhooks.TestDeliver(r.Context(), wh.ID)
	if err != nil {
		a.logger.Error("test webhook", "error", err)
		http.Redirect(w, r, "/settings/notifications?notice=test_failed", http.StatusSeeOther)
		return
	}
	a.audit(r, &session.User.ID, "settings.notifications.tested", "webhook", wh.ID)
	notice := "test_failed"
	if result.Status == "success" {
		notice = "test_ok"
	}
	http.Redirect(w, r, "/settings/notifications?notice="+notice, http.StatusSeeOther)
}

func (a *App) webhookDeleteConfirm(w http.ResponseWriter, r *http.Request) {
	session, wh, ok := a.loadWebhookPage(w, r)
	if !ok {
		return
	}
	_ = ui.Render(w, "confirm.html", ui.PageData{
		Title:     "Delete Webhook",
		User:      session.User,
		CSRF:      session.CSRFToken,
		ActiveNav: "settings",
		Form: map[string]string{
			"heading":      "Delete webhook",
			"message":      "This removes the endpoint and its delivery history. Changes will no longer be sent to it.",
			"subject":      wh.Name,
			"action":       "/settings/notifications/" + wh.ID + "/delete",
			"cancel":       "/settings/notifications",
			"confirm_text": "Delete webhook",
		},
	})
}

func (a *App) webhookDelete(w http.ResponseWriter, r *http.Request) {
	session, wh, ok := a.loadWebhookPage(w, r)
	if !ok {
		return
	}
	if !a.verifySessionCSRF(r, session) {
		http.Error(w, "Invalid form token", http.StatusForbidden)
		return
	}
	if err := a.store.DeleteWebhook(r.Context(), wh.ID); err != nil {
		a.logger.Error("delete webhook", "error", err)
		http.Error(w, "Unable to delete webhook", http.StatusInternalServerError)
		return
	}
	a.audit(r, &session.User.ID, "settings.notifications.deleted", "webhook", wh.ID)
	a.webhooks.Refresh(r.Context())
	http.Redirect(w, r, "/settings/notifications?notice=deleted", http.StatusSeeOther)
}

func (a *App) loadWebhookPage(w http.ResponseWriter, r *http.Request) (store.Session, store.Webhook, bool) {
	session, ok := a.requireAdmin(w, r)
	if !ok {
		return store.Session{}, store.Webhook{}, false
	}
	wh, err := a.store.GetWebhook(r.Context(), r.PathValue("id"))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			http.NotFound(w, r)
			return store.Session{}, store.Webhook{}, false
		}
		a.logger.Error("get webhook", "error", err)
		http.Error(w, "Unable to load webhook", http.StatusInternalServerError)
		return store.Session{}, store.Webhook{}, false
	}
	return session, wh, true
}

// sealWebhookSecret seals a raw signing secret for storage. An empty secret seals
// to an empty string (unsigned). A sealing failure (no encryption key) is logged
// and treated as unsigned rather than blocking the save.
func (a *App) sealWebhookSecret(raw string) string {
	if raw == "" || a.sealer == nil {
		return ""
	}
	sealed, err := a.sealer.Seal(raw)
	if err != nil {
		a.logger.Error("seal webhook secret", "error", err)
		return ""
	}
	return sealed
}

// parseWebhookForm validates the webhook form. Pure (no DB/sealer) so it is
// unit-tested directly; the raw signing secret is returned separately because
// sealing needs the app's sealer.
func parseWebhookForm(form url.Values) (store.WebhookInput, string, error) {
	name := strings.TrimSpace(form.Get("name"))
	if name == "" {
		return store.WebhookInput{}, "", errors.New("Webhook name is required.")
	}
	rawURL := strings.TrimSpace(form.Get("url"))
	u, err := url.Parse(rawURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return store.WebhookInput{}, "", errors.New("Enter a valid http:// or https:// URL.")
	}
	var events []string
	seen := make(map[string]bool, 4)
	for _, c := range form["event"] {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		if !webhook.ValidCategory(c) {
			return store.WebhookInput{}, "", errors.New("Unknown event category.")
		}
		if !seen[c] {
			seen[c] = true
			events = append(events, c)
		}
	}
	return store.WebhookInput{
		Name:    name,
		URL:     rawURL,
		Events:  events,
		Enabled: form.Get("enabled") != "",
	}, strings.TrimSpace(form.Get("secret")), nil
}

// submittedWebhookForm echoes the create form back on a validation error so the
// operator keeps what they typed (the secret is never echoed).
func submittedWebhookForm(form url.Values) map[string]string {
	out := map[string]string{
		"name": strings.TrimSpace(form.Get("name")),
		"url":  strings.TrimSpace(form.Get("url")),
	}
	if form.Get("enabled") != "" {
		out["enabled"] = "on"
	}
	for _, c := range form["event"] {
		if webhook.ValidCategory(c) {
			out["event_"+c] = "on"
		}
	}
	return out
}

func notificationsNotice(r *http.Request) string {
	switch r.URL.Query().Get("notice") {
	case "created":
		return "Webhook created."
	case "updated":
		return "Webhook updated."
	case "deleted":
		return "Webhook deleted."
	case "test_ok":
		return "Test delivery succeeded."
	case "test_failed":
		return "Test delivery failed — see the delivery log below."
	default:
		return ""
	}
}
