package app

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/devSealWare/LightIPAM/internal/store"
	"github.com/devSealWare/LightIPAM/internal/ui"
)

// Bulk edit applies a single change to a set of rows selected in a table. The
// markup works without JavaScript (checkboxes + an always-visible action bar);
// bulk.js only adds select-all and a live count. Every action is a
// CSRF-protected POST that writes an audit entry with the affected count, and
// destructive actions route through the shared confirm.html page first.

// bulkRequest is the parsed, validated form of a bulk POST. It is produced by
// parseBulkRequest (pure, unit-tested) and consumed by the entity handlers.
type bulkRequest struct {
	Action    string
	IDs       []string
	State     string // set_state
	Tag       string // tag_add / tag_remove
	VLAN      *int   // set_vlan (nil = clear)
	Confirmed bool
	SubnetID  string // addresses: redirect/return target
}

// bulkActions lists the actions allowed for each table. The action value posted
// by the form must be one of these for the given entity.
var bulkActions = map[string]map[string]bool{
	"subnets":   {"set_vlan": true, "tag_add": true, "tag_remove": true, "delete": true},
	"addresses": {"set_state": true, "tag_add": true, "tag_remove": true, "clear_device": true, "delete": true},
	"devices":   {"tag_add": true, "tag_remove": true, "delete": true},
}

// parseBulkRequest validates a bulk form for the named table ("subnets",
// "addresses", or "devices"), returning a typed request or a user-facing error.
func parseBulkRequest(form url.Values, entity string) (bulkRequest, error) {
	allowed, ok := bulkActions[entity]
	if !ok {
		return bulkRequest{}, fmt.Errorf("unknown bulk entity")
	}

	var ids []string
	for _, id := range form["ids"] {
		if id = strings.TrimSpace(id); id != "" {
			ids = append(ids, id)
		}
	}
	if len(ids) == 0 {
		return bulkRequest{}, fmt.Errorf("Select at least one row first.")
	}

	action := strings.TrimSpace(form.Get("action"))
	if action == "" {
		return bulkRequest{}, fmt.Errorf("Choose a bulk action.")
	}
	if !allowed[action] {
		return bulkRequest{}, fmt.Errorf("That action is not available here.")
	}

	req := bulkRequest{
		Action:    action,
		IDs:       ids,
		Confirmed: form.Get("confirmed") == "1",
		SubnetID:  strings.TrimSpace(form.Get("subnet_id")),
	}

	switch action {
	case "set_state":
		state := strings.TrimSpace(form.Get("state"))
		if !validAddressState(state) {
			return bulkRequest{}, fmt.Errorf("Choose a valid address state.")
		}
		req.State = state
	case "set_vlan":
		vlan, err := store.ParseVLAN(form.Get("vlan"))
		if err != nil {
			return bulkRequest{}, err
		}
		req.VLAN = vlan
	case "tag_add", "tag_remove":
		tag := strings.TrimSpace(form.Get("tag"))
		if tag == "" {
			return bulkRequest{}, fmt.Errorf("Enter a tag name.")
		}
		if len(tag) > 60 {
			return bulkRequest{}, fmt.Errorf("Tag names are limited to 60 characters.")
		}
		req.Tag = tag
	}
	return req, nil
}

func (a *App) subnetsBulk(w http.ResponseWriter, r *http.Request) {
	session, ok := a.requireSession(w, r)
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
	req, err := parseBulkRequest(r.Form, "subnets")
	if err != nil {
		a.renderSubnetsError(w, r, session, err.Error())
		return
	}
	if req.Action == "delete" && !req.Confirmed {
		a.renderBulkDeleteConfirm(w, session, "subnets",
			"Delete subnets",
			"This removes the selected subnets and detaches any touched address records from them.",
			countSubject(len(req.IDs), "subnet"),
			"/subnets/bulk", "/subnets", "Delete subnets", req.IDs, "")
		return
	}

	uid := session.User.ID
	var (
		count        int
		action, meta string
	)
	switch req.Action {
	case "set_vlan":
		count, err = a.store.BulkSetSubnetVLAN(r.Context(), req.IDs, req.VLAN)
		action = "subnet.bulk_vlan_set"
		if req.VLAN != nil {
			meta = intString(*req.VLAN)
		} else {
			meta = "cleared"
		}
	case "tag_add":
		count, err = a.store.BulkAddTag(r.Context(), "subnet", req.IDs, req.Tag)
		action, meta = "subnet.bulk_tag_added", req.Tag
	case "tag_remove":
		count, err = a.store.BulkRemoveTag(r.Context(), "subnet", req.IDs, req.Tag)
		action, meta = "subnet.bulk_tag_removed", req.Tag
	case "delete":
		count, err = a.store.BulkDeleteSubnets(r.Context(), req.IDs)
		action = "subnet.bulk_deleted"
	}
	if err != nil {
		a.renderSubnetsError(w, r, session, "Unable to apply that bulk action.")
		return
	}
	a.auditBulk(r, &uid, action, "subnet", len(req.IDs), count, meta)
	http.Redirect(w, r, "/subnets", http.StatusSeeOther)
}

func (a *App) addressesBulk(w http.ResponseWriter, r *http.Request) {
	session, ok := a.requireSession(w, r)
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
	req, err := parseBulkRequest(r.Form, "addresses")
	if err != nil {
		a.renderAddressesBulkError(w, r, session, strings.TrimSpace(r.FormValue("subnet_id")), err.Error())
		return
	}
	returnTo := "/subnets"
	if req.SubnetID != "" {
		returnTo = "/subnets/" + req.SubnetID
	}
	if req.Action == "delete" && !req.Confirmed {
		a.renderBulkDeleteConfirm(w, session, "subnets",
			"Remove addresses",
			"This removes the selected sparse address records. They can be recreated later.",
			countSubject(len(req.IDs), "address"),
			"/addresses/bulk", returnTo, "Remove addresses", req.IDs, req.SubnetID)
		return
	}

	uid := session.User.ID
	var (
		count        int
		action, meta string
	)
	switch req.Action {
	case "set_state":
		count, err = a.store.BulkSetAddressState(r.Context(), req.IDs, req.State)
		action, meta = "address.bulk_state_set", req.State
	case "clear_device":
		count, err = a.store.BulkClearAddressDevice(r.Context(), req.IDs)
		action = "address.bulk_device_cleared"
	case "tag_add":
		count, err = a.store.BulkAddTag(r.Context(), "ip_address", req.IDs, req.Tag)
		action, meta = "address.bulk_tag_added", req.Tag
	case "tag_remove":
		count, err = a.store.BulkRemoveTag(r.Context(), "ip_address", req.IDs, req.Tag)
		action, meta = "address.bulk_tag_removed", req.Tag
	case "delete":
		count, err = a.store.BulkDeleteAddresses(r.Context(), req.IDs)
		action = "address.bulk_deleted"
	}
	if err != nil {
		a.renderAddressesBulkError(w, r, session, req.SubnetID, "Unable to apply that bulk action.")
		return
	}
	a.auditBulk(r, &uid, action, "ip_address", len(req.IDs), count, meta)
	http.Redirect(w, r, returnTo, http.StatusSeeOther)
}

func (a *App) devicesBulk(w http.ResponseWriter, r *http.Request) {
	session, ok := a.requireSession(w, r)
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
	req, err := parseBulkRequest(r.Form, "devices")
	if err != nil {
		a.renderDevicesError(w, r, session, err.Error())
		return
	}
	if req.Action == "delete" && !req.Confirmed {
		a.renderBulkDeleteConfirm(w, session, "devices",
			"Delete devices",
			"This deletes the selected devices, removes their MAC addresses, and leaves linked IP records unassigned.",
			countSubject(len(req.IDs), "device"),
			"/devices/bulk", "/devices", "Delete devices", req.IDs, "")
		return
	}

	uid := session.User.ID
	var (
		count        int
		action, meta string
	)
	switch req.Action {
	case "tag_add":
		count, err = a.store.BulkAddTag(r.Context(), "device", req.IDs, req.Tag)
		action, meta = "device.bulk_tag_added", req.Tag
	case "tag_remove":
		count, err = a.store.BulkRemoveTag(r.Context(), "device", req.IDs, req.Tag)
		action, meta = "device.bulk_tag_removed", req.Tag
	case "delete":
		count, err = a.store.BulkDeleteDevices(r.Context(), req.IDs)
		action = "device.bulk_deleted"
	}
	if err != nil {
		a.renderDevicesError(w, r, session, "Unable to apply that bulk action.")
		return
	}
	a.auditBulk(r, &uid, action, "device", len(req.IDs), count, meta)
	http.Redirect(w, r, "/devices", http.StatusSeeOther)
}

// renderBulkDeleteConfirm shows the shared confirm page for a destructive bulk
// action, carrying the selected ids forward as hidden inputs so the confirmed
// POST re-runs the same delete.
func (a *App) renderBulkDeleteConfirm(w http.ResponseWriter, session store.Session, nav, heading, message, subject, action, cancel, confirmText string, ids []string, subnetID string) {
	form := map[string]string{
		"heading":      heading,
		"message":      message,
		"subject":      subject,
		"action":       action,
		"cancel":       cancel,
		"confirm_text": confirmText,
		"ids":          strings.Join(ids, ","),
		"bulk_action":  "delete",
	}
	if subnetID != "" {
		form["subnet_id"] = subnetID
	}
	_ = ui.Render(w, "confirm.html", ui.PageData{
		Title:     confirmText,
		User:      session.User,
		CSRF:      session.CSRFToken,
		ActiveNav: nav,
		Form:      form,
	})
}

func (a *App) renderSubnetsError(w http.ResponseWriter, r *http.Request, session store.Session, message string) {
	subnets, err := a.store.ListSubnets(r.Context())
	if err != nil {
		a.logger.Error("list subnets", "error", err)
		http.Error(w, "Unable to load subnets", http.StatusInternalServerError)
		return
	}
	_ = ui.Render(w, "subnets.html", ui.PageData{
		Title:     "Subnets",
		Error:     message,
		User:      session.User,
		CSRF:      session.CSRFToken,
		Subnets:   subnets,
		ActiveNav: "subnets",
	})
}

func (a *App) renderDevicesError(w http.ResponseWriter, r *http.Request, session store.Session, message string) {
	groups, err := a.store.ListDeviceGroups(r.Context())
	if err != nil {
		a.logger.Error("list device groups", "error", err)
		http.Error(w, "Unable to load devices", http.StatusInternalServerError)
		return
	}
	_ = ui.Render(w, "devices.html", ui.PageData{
		Title:        "Devices",
		Error:        message,
		User:         session.User,
		CSRF:         session.CSRFToken,
		DeviceGroups: groups,
		ActiveNav:    "devices",
	})
}

func (a *App) renderAddressesBulkError(w http.ResponseWriter, r *http.Request, session store.Session, subnetID, message string) {
	if subnetID != "" {
		if subnet, err := a.store.GetSubnet(r.Context(), subnetID); err == nil {
			a.renderSubnetDetailError(w, r, session, subnet, message)
			return
		}
	}
	http.Error(w, message, http.StatusBadRequest)
}

// auditBulk records a bulk mutation. subject_id is left empty (the action spans
// many rows); selected/affected counts and any value ride in the metadata.
func (a *App) auditBulk(r *http.Request, actorUserID *string, action, subjectType string, selected, affected int, value string) {
	payload := map[string]any{"selected": selected, "affected": affected}
	if value != "" {
		payload["value"] = value
	}
	metadata, err := json.Marshal(payload)
	if err != nil {
		metadata = []byte("{}")
	}
	if err := a.store.CreateAuditLog(r.Context(), actorUserID, action, subjectType, "", string(metadata)); err != nil {
		a.logger.Error("create audit log", "error", err, "action", action)
	}
}

func countSubject(n int, noun string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, noun)
	}
	return fmt.Sprintf("%d %ss", n, noun)
}
