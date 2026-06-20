package app

import (
	"errors"
	"net/http"
	"strings"

	"github.com/devSealWare/LightIPAM/internal/store"
	"github.com/devSealWare/LightIPAM/internal/ui"
)

// customFieldValuePrefix names the form inputs that carry a custom-field value
// on the entity forms: cf_<definition-id>.
const customFieldValuePrefix = "cf_"

// parseCustomFieldValues collects submitted custom-field values from a parsed
// form, keyed by field-definition id. The caller must have run ParseForm. The
// store bounds these to the entity type's real definitions, so extra keys are
// harmless.
func parseCustomFieldValues(r *http.Request) map[string]string {
	values := make(map[string]string)
	for key, vals := range r.PostForm {
		if !strings.HasPrefix(key, customFieldValuePrefix) || len(vals) == 0 {
			continue
		}
		id := strings.TrimPrefix(key, customFieldValuePrefix)
		if id == "" {
			continue
		}
		values[id] = vals[0]
	}
	return values
}

// saveCustomFieldValues persists an entity's custom-field values after a create
// or update. A storage error is logged but not surfaced: the entity itself was
// already saved, and custom fields are supplemental metadata.
func (a *App) saveCustomFieldValues(r *http.Request, entityType, entityID string) {
	if err := a.store.SetCustomFieldValues(r.Context(), entityType, entityID, parseCustomFieldValues(r)); err != nil {
		a.logger.Error("set custom field values", "error", err, "entity_type", entityType, "entity_id", entityID)
	}
}

// loadCustomFields returns an entity's fields + values for a form or detail
// page, logging (but not failing on) an error so a custom-fields hiccup never
// breaks a core IPAM page.
func (a *App) loadCustomFields(r *http.Request, entityType, entityID string) []store.CustomFieldValue {
	values, err := a.store.CustomFieldValues(r.Context(), entityType, entityID)
	if err != nil {
		a.logger.Error("load custom fields", "error", err, "entity_type", entityType, "entity_id", entityID)
		return nil
	}
	return values
}

func (a *App) settingsCustomFields(w http.ResponseWriter, r *http.Request) {
	session, ok := a.requireAdmin(w, r)
	if !ok {
		return
	}
	a.renderCustomFieldsTab(w, r, session, nil, "", customFieldsNotice(r))
}

func (a *App) customFieldCreate(w http.ResponseWriter, r *http.Request) {
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
	entityType := strings.TrimSpace(r.FormValue("entity_type"))
	name := strings.TrimSpace(r.FormValue("name"))
	form := map[string]string{"entity_type": entityType, "name": name}
	if !store.ValidCustomFieldEntityType(entityType) {
		a.renderCustomFieldsTab(w, r, session, form, "Choose what the field applies to.", "")
		return
	}
	if name == "" {
		a.renderCustomFieldsTab(w, r, session, form, "Enter a field name.", "")
		return
	}
	def, err := a.store.CreateCustomFieldDef(r.Context(), entityType, name)
	if err != nil {
		if errors.Is(err, store.ErrDuplicate) {
			a.renderCustomFieldsTab(w, r, session, form, "A field with that name already exists for that type.", "")
			return
		}
		a.logger.Error("create custom field", "error", err)
		a.renderCustomFieldsTab(w, r, session, form, "Unable to create the field.", "")
		return
	}
	a.auditMeta(r, &session.User.ID, "custom_field.created", "custom_field", def.ID, map[string]string{
		"entity_type": def.EntityType,
		"name":        def.Name,
	})
	http.Redirect(w, r, "/settings/custom-fields?notice=created", http.StatusSeeOther)
}

func (a *App) customFieldDeleteConfirm(w http.ResponseWriter, r *http.Request) {
	session, def, ok := a.loadCustomFieldDef(w, r)
	if !ok {
		return
	}
	_ = ui.Render(w, "confirm.html", ui.PageData{
		Title:     "Delete Custom Field",
		User:      session.User,
		CSRF:      session.CSRFToken,
		ActiveNav: "settings",
		Form: map[string]string{
			"heading":      "Delete custom field",
			"message":      "This deletes the field definition and every value stored for it on existing records. This cannot be undone.",
			"subject":      def.Name + " (" + entityTypeLabelFor(def.EntityType) + ")",
			"action":       "/settings/custom-fields/" + def.ID + "/delete",
			"cancel":       "/settings/custom-fields",
			"confirm_text": "Delete field",
		},
	})
}

func (a *App) customFieldDelete(w http.ResponseWriter, r *http.Request) {
	session, def, ok := a.loadCustomFieldDef(w, r)
	if !ok {
		return
	}
	if !a.verifySessionCSRF(r, session) {
		http.Error(w, "Invalid form token", http.StatusForbidden)
		return
	}
	if err := a.store.DeleteCustomFieldDef(r.Context(), def.ID); err != nil {
		a.logger.Error("delete custom field", "error", err)
		http.Error(w, "Unable to delete the field", http.StatusInternalServerError)
		return
	}
	a.auditMeta(r, &session.User.ID, "custom_field.deleted", "custom_field", def.ID, map[string]string{
		"entity_type": def.EntityType,
		"name":        def.Name,
	})
	http.Redirect(w, r, "/settings/custom-fields?notice=deleted", http.StatusSeeOther)
}

// loadCustomFieldDef resolves the admin session and the target field definition.
func (a *App) loadCustomFieldDef(w http.ResponseWriter, r *http.Request) (store.Session, store.CustomFieldDef, bool) {
	session, ok := a.requireAdmin(w, r)
	if !ok {
		return store.Session{}, store.CustomFieldDef{}, false
	}
	def, err := a.store.GetCustomFieldDef(r.Context(), r.PathValue("id"))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			http.NotFound(w, r)
			return store.Session{}, store.CustomFieldDef{}, false
		}
		a.logger.Error("get custom field", "error", err)
		http.Error(w, "Unable to load custom field", http.StatusInternalServerError)
		return store.Session{}, store.CustomFieldDef{}, false
	}
	return session, def, true
}

// renderCustomFieldsTab renders the Settings page on its Custom Fields tab.
func (a *App) renderCustomFieldsTab(w http.ResponseWriter, r *http.Request, session store.Session, form map[string]string, errMsg, notice string) {
	defs, err := a.store.ListAllCustomFieldDefs(r.Context())
	if err != nil {
		a.logger.Error("list custom fields", "error", err)
		http.Error(w, "Unable to load custom fields", http.StatusInternalServerError)
		return
	}
	if form == nil {
		form = map[string]string{"entity_type": store.CustomFieldDevice}
	}
	_ = ui.Render(w, "settings.html", ui.PageData{
		Title:           "Settings",
		User:            session.User,
		CSRF:            session.CSRFToken,
		Error:           errMsg,
		SuccessMessage:  notice,
		CustomFieldDefs: defs,
		Form:            form,
		ActiveNav:       "settings",
		ActiveTab:       "customfields",
	})
}

// customFieldsNotice maps the post-redirect ?notice marker to a banner message.
func customFieldsNotice(r *http.Request) string {
	switch r.URL.Query().Get("notice") {
	case "created":
		return "Custom field created."
	case "deleted":
		return "Custom field deleted."
	default:
		return ""
	}
}

// entityTypeLabelFor mirrors the template's entityTypeLabel for use in handler
// strings (the delete-confirmation subject).
func entityTypeLabelFor(entityType string) string {
	switch entityType {
	case store.CustomFieldSubnet:
		return "Subnet"
	case store.CustomFieldAddress:
		return "Address"
	case store.CustomFieldDevice:
		return "Device"
	default:
		return entityType
	}
}
