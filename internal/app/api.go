package app

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/devSealWare/LightIPAM/internal/auth"
	"github.com/devSealWare/LightIPAM/internal/ipam"
	"github.com/devSealWare/LightIPAM/internal/store"
)

// normalizeCIDROrEmpty validates an IPv4 CIDR, returning a friendly message on
// failure (the API never echoes raw parser errors).
func normalizeCIDROrEmpty(raw string) (string, string) {
	cidr, err := ipam.NormalizeCIDR(strings.TrimSpace(raw))
	if err != nil {
		return "", "cidr must be a valid IPv4 CIDR such as 192.168.10.0/24."
	}
	return cidr, ""
}

func normalizeIPv4OrEmpty(raw string) (string, string) {
	addr, err := ipam.NormalizeIPv4(strings.TrimSpace(raw))
	if err != nil {
		return "", "address must be a valid IPv4 address."
	}
	return addr, ""
}

// Machine API (Phase 6, ADR 0024). A small JSON read/write API under /api/v1,
// authenticated by a per-user bearer token instead of the session cookie, so the
// CLI (cmd/lightipam-cli) and other automation can manage IPAM. A token inherits
// its owner's role, so the same admin/viewer authorization applies: read is open
// to any valid token, writes require a write-capable (admin) role. The API is
// cookie-free, so it is exempt from CSRF; mutations are still audited (and fan out
// to change webhooks) exactly like the web UI.

// registerAPIRoutes wires the JSON API onto the mux. Read handlers pass write=false
// (any valid token); mutations pass write=true (admin role required).
func (a *App) registerAPIRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/whoami", a.apiHandler(false, a.apiWhoami))

	mux.HandleFunc("GET /api/v1/subnets", a.apiHandler(false, a.apiListSubnets))
	mux.HandleFunc("POST /api/v1/subnets", a.apiHandler(true, a.apiCreateSubnet))
	mux.HandleFunc("GET /api/v1/subnets/{id}", a.apiHandler(false, a.apiGetSubnet))
	mux.HandleFunc("PUT /api/v1/subnets/{id}", a.apiHandler(true, a.apiUpdateSubnet))
	mux.HandleFunc("DELETE /api/v1/subnets/{id}", a.apiHandler(true, a.apiDeleteSubnet))

	mux.HandleFunc("GET /api/v1/subnets/{id}/addresses", a.apiHandler(false, a.apiListAddresses))
	mux.HandleFunc("POST /api/v1/subnets/{id}/addresses", a.apiHandler(true, a.apiCreateAddress))
	mux.HandleFunc("GET /api/v1/addresses/{id}", a.apiHandler(false, a.apiGetAddress))
	mux.HandleFunc("PUT /api/v1/addresses/{id}", a.apiHandler(true, a.apiUpdateAddress))
	mux.HandleFunc("DELETE /api/v1/addresses/{id}", a.apiHandler(true, a.apiDeleteAddress))

	mux.HandleFunc("GET /api/v1/devices", a.apiHandler(false, a.apiListDevices))
	mux.HandleFunc("POST /api/v1/devices", a.apiHandler(true, a.apiCreateDevice))
	mux.HandleFunc("GET /api/v1/devices/{id}", a.apiHandler(false, a.apiGetDevice))
	mux.HandleFunc("PUT /api/v1/devices/{id}", a.apiHandler(true, a.apiUpdateDevice))
	mux.HandleFunc("DELETE /api/v1/devices/{id}", a.apiHandler(true, a.apiDeleteDevice))

	// Bare (method-less) fallback per registered path: ServeMux only auto-emits its
	// plain-text 405 when no pattern at all matches an unsupported method. Registering
	// these less-specific catch-alls means unsupported methods fall through to them
	// instead, keeping every /api/v1 response — including 405s — in the JSON envelope.
	for _, path := range []string{
		"/api/v1/whoami",
		"/api/v1/subnets",
		"/api/v1/subnets/{id}",
		"/api/v1/subnets/{id}/addresses",
		"/api/v1/addresses/{id}",
		"/api/v1/devices",
		"/api/v1/devices/{id}",
	} {
		mux.HandleFunc(path, apiMethodNotAllowed)
	}
}

func apiMethodNotAllowed(w http.ResponseWriter, r *http.Request) {
	apiError(w, http.StatusMethodNotAllowed, "method not allowed")
}

// apiHandler authenticates the bearer token, enforces the role for writes, and
// then invokes fn with the resolved user.
func (a *App) apiHandler(write bool, fn func(http.ResponseWriter, *http.Request, store.User)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, ok := a.authenticateAPI(r)
		if !ok {
			apiError(w, http.StatusUnauthorized, "Provide a valid API token in the Authorization: Bearer header.")
			return
		}
		if write && !canWrite(user.Role) {
			apiError(w, http.StatusForbidden, "This token is read-only (viewer role).")
			return
		}
		fn(w, r, user)
	}
}

// authenticateAPI resolves the request's bearer token to a user.
func (a *App) authenticateAPI(r *http.Request) (store.User, bool) {
	const prefix = "Bearer "
	header := r.Header.Get("Authorization")
	if len(header) <= len(prefix) || !strings.EqualFold(header[:len(prefix)], prefix) {
		return store.User{}, false
	}
	token := strings.TrimSpace(header[len(prefix):])
	if token == "" {
		return store.User{}, false
	}
	user, err := a.store.AuthenticateAPIToken(r.Context(), auth.HashToken(token))
	if err != nil {
		return store.User{}, false
	}
	return user, true
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func apiError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// decodeJSON reads a bounded JSON request body, rejecting unknown fields so a
// typo in a client is reported rather than silently ignored.
func decodeJSON(r *http.Request, v any) error {
	dec := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	return nil
}

// apiHandleStoreErr writes the right status for a store error and reports whether
// it handled one (so callers can early-return).
func apiHandleStoreErr(w http.ResponseWriter, err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, store.ErrNotFound) {
		apiError(w, http.StatusNotFound, "Not found.")
		return true
	}
	apiError(w, http.StatusInternalServerError, "Internal error.")
	return true
}

// --- JSON shapes ---

type subnetJSON struct {
	ID           string `json:"id"`
	CIDR         string `json:"cidr"`
	Name         string `json:"name"`
	VLAN         *int   `json:"vlan"`
	SiteID       string `json:"site_id"`
	Description  string `json:"description"`
	AddressCount int    `json:"address_count"`
}

type subnetReq struct {
	CIDR        string `json:"cidr"`
	Name        string `json:"name"`
	VLAN        *int   `json:"vlan"`
	SiteID      string `json:"site_id"`
	Description string `json:"description"`
}

type addressJSON struct {
	ID       string `json:"id"`
	SubnetID string `json:"subnet_id"`
	Address  string `json:"address"`
	State    string `json:"state"`
	Hostname string `json:"hostname"`
	DeviceID string `json:"device_id"`
	Notes    string `json:"notes"`
}

type addressReq struct {
	Address  string `json:"address"`
	State    string `json:"state"`
	Hostname string `json:"hostname"`
	DeviceID string `json:"device_id"`
	Notes    string `json:"notes"`
}

type deviceJSON struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

type deviceReq struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

func subnetToJSON(s store.Subnet) subnetJSON {
	return subnetJSON{ID: s.ID, CIDR: s.CIDR, Name: s.Name, VLAN: s.VLAN, SiteID: s.SiteID, Description: s.Description, AddressCount: s.AddressCount}
}

func addressToJSON(a store.IPAddress) addressJSON {
	return addressJSON{ID: a.ID, SubnetID: a.SubnetID, Address: a.Address, State: a.State, Hostname: a.Hostname, DeviceID: a.DeviceID, Notes: a.Notes}
}

func deviceToJSON(d store.Device) deviceJSON {
	return deviceJSON{ID: d.ID, Name: d.Name, Description: d.Description}
}

// --- whoami ---

func (a *App) apiWhoami(w http.ResponseWriter, r *http.Request, user store.User) {
	writeJSON(w, http.StatusOK, map[string]any{
		"id":        user.ID,
		"username":  user.Username,
		"role":      user.Role,
		"can_write": canWrite(user.Role),
	})
}

// --- subnets ---

func (a *App) apiListSubnets(w http.ResponseWriter, r *http.Request, _ store.User) {
	subnets, err := a.store.ListSubnets(r.Context())
	if apiHandleStoreErr(w, err) {
		return
	}
	out := make([]subnetJSON, 0, len(subnets))
	for _, s := range subnets {
		out = append(out, subnetToJSON(s))
	}
	writeJSON(w, http.StatusOK, map[string]any{"subnets": out})
}

func (a *App) apiGetSubnet(w http.ResponseWriter, r *http.Request, _ store.User) {
	s, err := a.store.GetSubnet(r.Context(), r.PathValue("id"))
	if apiHandleStoreErr(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, subnetToJSON(s))
}

func (a *App) apiCreateSubnet(w http.ResponseWriter, r *http.Request, user store.User) {
	var req subnetReq
	if err := decodeJSON(r, &req); err != nil {
		apiError(w, http.StatusBadRequest, "Invalid JSON body.")
		return
	}
	input, msg := req.toInput()
	if msg != "" {
		apiError(w, http.StatusBadRequest, msg)
		return
	}
	s, err := a.store.CreateSubnet(r.Context(), input)
	if err != nil {
		apiError(w, http.StatusBadRequest, subnetError(err))
		return
	}
	a.auditMeta(r, &user.ID, "subnet.created", "subnet", s.ID, map[string]string{"cidr": s.CIDR, "name": s.Name})
	writeJSON(w, http.StatusCreated, subnetToJSON(s))
}

func (a *App) apiUpdateSubnet(w http.ResponseWriter, r *http.Request, user store.User) {
	var req subnetReq
	if err := decodeJSON(r, &req); err != nil {
		apiError(w, http.StatusBadRequest, "Invalid JSON body.")
		return
	}
	input, msg := req.toInput()
	if msg != "" {
		apiError(w, http.StatusBadRequest, msg)
		return
	}
	s, err := a.store.UpdateSubnet(r.Context(), r.PathValue("id"), input)
	if errors.Is(err, store.ErrNotFound) {
		apiError(w, http.StatusNotFound, "Not found.")
		return
	}
	if err != nil {
		apiError(w, http.StatusBadRequest, subnetError(err))
		return
	}
	a.auditMeta(r, &user.ID, "subnet.updated", "subnet", s.ID, map[string]string{"cidr": s.CIDR, "name": s.Name})
	writeJSON(w, http.StatusOK, subnetToJSON(s))
}

func (a *App) apiDeleteSubnet(w http.ResponseWriter, r *http.Request, user store.User) {
	id := r.PathValue("id")
	if err := a.store.DeleteSubnet(r.Context(), id); apiHandleStoreErr(w, err) {
		return
	}
	a.audit(r, &user.ID, "subnet.deleted", "subnet", id)
	w.WriteHeader(http.StatusNoContent)
}

func (req subnetReq) toInput() (store.SubnetInput, string) {
	cidr, err := normalizeCIDROrEmpty(req.CIDR)
	if err != "" {
		return store.SubnetInput{}, err
	}
	if strings.TrimSpace(req.Name) == "" {
		return store.SubnetInput{}, "name is required."
	}
	if req.VLAN != nil && (*req.VLAN < 1 || *req.VLAN > 4094) {
		return store.SubnetInput{}, "vlan must be between 1 and 4094."
	}
	siteID := strings.TrimSpace(req.SiteID)
	if siteID == "" {
		siteID = "default"
	}
	return store.SubnetInput{
		SiteID:      siteID,
		CIDR:        cidr,
		Name:        strings.TrimSpace(req.Name),
		VLAN:        req.VLAN,
		Description: req.Description,
	}, ""
}

// --- addresses ---

func (a *App) apiListAddresses(w http.ResponseWriter, r *http.Request, _ store.User) {
	subnet, err := a.store.GetSubnet(r.Context(), r.PathValue("id"))
	if apiHandleStoreErr(w, err) {
		return
	}
	addresses, err := a.store.ListAddresses(r.Context(), subnet.ID)
	if apiHandleStoreErr(w, err) {
		return
	}
	out := make([]addressJSON, 0, len(addresses))
	for _, addr := range addresses {
		out = append(out, addressToJSON(addr))
	}
	writeJSON(w, http.StatusOK, map[string]any{"addresses": out})
}

func (a *App) apiGetAddress(w http.ResponseWriter, r *http.Request, _ store.User) {
	addr, err := a.store.GetAddress(r.Context(), r.PathValue("id"))
	if apiHandleStoreErr(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, addressToJSON(addr))
}

func (a *App) apiCreateAddress(w http.ResponseWriter, r *http.Request, user store.User) {
	subnet, err := a.store.GetSubnet(r.Context(), r.PathValue("id"))
	if apiHandleStoreErr(w, err) {
		return
	}
	var req addressReq
	if err := decodeJSON(r, &req); err != nil {
		apiError(w, http.StatusBadRequest, "Invalid JSON body.")
		return
	}
	input, msg := req.toInput()
	if msg != "" {
		apiError(w, http.StatusBadRequest, msg)
		return
	}
	addr, err := a.store.CreateAddress(r.Context(), subnet, input)
	if err != nil {
		apiError(w, http.StatusBadRequest, addressError(err))
		return
	}
	a.auditMeta(r, &user.ID, "address.created", "ip_address", addr.ID, map[string]string{"address": addr.Address, "hostname": addr.Hostname})
	writeJSON(w, http.StatusCreated, addressToJSON(addr))
}

func (a *App) apiUpdateAddress(w http.ResponseWriter, r *http.Request, user store.User) {
	existing, err := a.store.GetAddress(r.Context(), r.PathValue("id"))
	if apiHandleStoreErr(w, err) {
		return
	}
	subnet, err := a.store.GetSubnet(r.Context(), existing.SubnetID)
	if apiHandleStoreErr(w, err) {
		return
	}
	var req addressReq
	if err := decodeJSON(r, &req); err != nil {
		apiError(w, http.StatusBadRequest, "Invalid JSON body.")
		return
	}
	input, msg := req.toInput()
	if msg != "" {
		apiError(w, http.StatusBadRequest, msg)
		return
	}
	addr, err := a.store.UpdateAddress(r.Context(), existing.ID, subnet, input)
	if err != nil {
		apiError(w, http.StatusBadRequest, addressError(err))
		return
	}
	a.auditMeta(r, &user.ID, "address.updated", "ip_address", addr.ID, map[string]string{"address": addr.Address, "hostname": addr.Hostname})
	writeJSON(w, http.StatusOK, addressToJSON(addr))
}

func (a *App) apiDeleteAddress(w http.ResponseWriter, r *http.Request, user store.User) {
	id := r.PathValue("id")
	if err := a.store.DeleteAddress(r.Context(), id); apiHandleStoreErr(w, err) {
		return
	}
	a.audit(r, &user.ID, "address.deleted", "ip_address", id)
	w.WriteHeader(http.StatusNoContent)
}

func (req addressReq) toInput() (store.AddressInput, string) {
	address, err := normalizeIPv4OrEmpty(req.Address)
	if err != "" {
		return store.AddressInput{}, err
	}
	state := strings.TrimSpace(req.State)
	if state == "" {
		state = "assigned"
	}
	if !validAddressState(state) {
		return store.AddressInput{}, "state must be available, reserved, assigned, deprecated, or conflict."
	}
	return store.AddressInput{
		Address:  address,
		State:    state,
		DeviceID: strings.TrimSpace(req.DeviceID),
		Hostname: req.Hostname,
		Notes:    req.Notes,
	}, ""
}

// --- devices ---

func (a *App) apiListDevices(w http.ResponseWriter, r *http.Request, _ store.User) {
	devices, err := a.store.ListDevices(r.Context())
	if apiHandleStoreErr(w, err) {
		return
	}
	out := make([]deviceJSON, 0, len(devices))
	for _, d := range devices {
		out = append(out, deviceToJSON(d))
	}
	writeJSON(w, http.StatusOK, map[string]any{"devices": out})
}

func (a *App) apiGetDevice(w http.ResponseWriter, r *http.Request, _ store.User) {
	d, err := a.store.GetDevice(r.Context(), r.PathValue("id"))
	if apiHandleStoreErr(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, deviceToJSON(d))
}

func (a *App) apiCreateDevice(w http.ResponseWriter, r *http.Request, user store.User) {
	var req deviceReq
	if err := decodeJSON(r, &req); err != nil {
		apiError(w, http.StatusBadRequest, "Invalid JSON body.")
		return
	}
	if strings.TrimSpace(req.Name) == "" {
		apiError(w, http.StatusBadRequest, "name is required.")
		return
	}
	d, err := a.store.CreateDevice(r.Context(), store.DeviceInput{Name: strings.TrimSpace(req.Name), Description: req.Description})
	if apiHandleStoreErr(w, err) {
		return
	}
	a.auditMeta(r, &user.ID, "device.created", "device", d.ID, map[string]string{"name": d.Name})
	writeJSON(w, http.StatusCreated, deviceToJSON(d))
}

func (a *App) apiUpdateDevice(w http.ResponseWriter, r *http.Request, user store.User) {
	var req deviceReq
	if err := decodeJSON(r, &req); err != nil {
		apiError(w, http.StatusBadRequest, "Invalid JSON body.")
		return
	}
	if strings.TrimSpace(req.Name) == "" {
		apiError(w, http.StatusBadRequest, "name is required.")
		return
	}
	d, err := a.store.UpdateDevice(r.Context(), r.PathValue("id"), store.DeviceInput{Name: strings.TrimSpace(req.Name), Description: req.Description})
	if apiHandleStoreErr(w, err) {
		return
	}
	a.auditMeta(r, &user.ID, "device.updated", "device", d.ID, map[string]string{"name": d.Name})
	writeJSON(w, http.StatusOK, deviceToJSON(d))
}

func (a *App) apiDeleteDevice(w http.ResponseWriter, r *http.Request, user store.User) {
	id := r.PathValue("id")
	if err := a.store.DeleteDevice(r.Context(), id); apiHandleStoreErr(w, err) {
		return
	}
	a.audit(r, &user.ID, "device.deleted", "device", id)
	w.WriteHeader(http.StatusNoContent)
}
