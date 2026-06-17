package app

import (
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/devSealWare/LightIPAM/internal/auth"
	"github.com/devSealWare/LightIPAM/internal/config"
	"github.com/devSealWare/LightIPAM/internal/ipam"
	"github.com/devSealWare/LightIPAM/internal/scanner/orchestrator"
	"github.com/devSealWare/LightIPAM/internal/store"
	"github.com/devSealWare/LightIPAM/internal/ui"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	sessionCookie = "lightipam_session"
	csrfCookie    = "lightipam_csrf"
)

type Options struct {
	Config config.Config
	DB     *pgxpool.Pool
	Logger *slog.Logger
	Scans  *orchestrator.Service
}

type App struct {
	cfg    config.Config
	store  *store.Store
	logger *slog.Logger
	scans  *orchestrator.Service
}

func New(options Options) http.Handler {
	app := &App{
		cfg:    options.Config,
		store:  store.New(options.DB),
		logger: options.Logger,
		scans:  options.Scans,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", app.health)
	mux.HandleFunc("GET /static/app.css", ui.StaticCSS)
	mux.HandleFunc("GET /static/columns.js", ui.StaticJS)
	mux.HandleFunc("GET /static/scan_form.js", ui.ScanFormJS)
	mux.HandleFunc("GET /static/bulk.js", ui.BulkJS)
	mux.HandleFunc("GET /", app.dashboard)
	mux.HandleFunc("GET /search", app.search)
	mux.HandleFunc("GET /bootstrap", app.bootstrapForm)
	mux.HandleFunc("POST /bootstrap", app.bootstrapSubmit)
	mux.HandleFunc("GET /login", app.loginForm)
	mux.HandleFunc("POST /login", app.loginSubmit)
	mux.HandleFunc("POST /logout", app.logout)
	mux.HandleFunc("GET /subnets", app.subnetsIndex)
	mux.HandleFunc("GET /subnets/new", app.subnetNew)
	mux.HandleFunc("POST /subnets", app.subnetCreate)
	mux.HandleFunc("POST /subnets/bulk", app.subnetsBulk)
	mux.HandleFunc("POST /addresses/bulk", app.addressesBulk)
	mux.HandleFunc("GET /subnets/{id}", app.subnetShow)
	mux.HandleFunc("GET /subnets/{id}/edit", app.subnetEdit)
	mux.HandleFunc("POST /subnets/{id}", app.subnetUpdate)
	mux.HandleFunc("GET /subnets/{id}/delete", app.subnetDeleteConfirm)
	mux.HandleFunc("POST /subnets/{id}/delete", app.subnetDelete)
	mux.HandleFunc("POST /subnets/{id}/addresses", app.addressCreate)
	mux.HandleFunc("GET /addresses/{id}/edit", app.addressEdit)
	mux.HandleFunc("POST /addresses/{id}", app.addressUpdate)
	mux.HandleFunc("GET /addresses/{id}/delete", app.addressDeleteConfirm)
	mux.HandleFunc("POST /addresses/{id}/delete", app.addressDelete)
	mux.HandleFunc("GET /devices", app.devicesIndex)
	mux.HandleFunc("GET /devices/new", app.deviceNew)
	mux.HandleFunc("POST /devices", app.deviceCreate)
	mux.HandleFunc("POST /devices/bulk", app.devicesBulk)
	mux.HandleFunc("GET /devices/{id}", app.deviceShow)
	mux.HandleFunc("GET /devices/{id}/edit", app.deviceEdit)
	mux.HandleFunc("POST /devices/{id}", app.deviceUpdate)
	mux.HandleFunc("GET /devices/{id}/delete", app.deviceDeleteConfirm)
	mux.HandleFunc("POST /devices/{id}/delete", app.deviceDelete)
	mux.HandleFunc("POST /devices/{id}/macs", app.macCreate)
	mux.HandleFunc("GET /macs/{id}/delete", app.macDeleteConfirm)
	mux.HandleFunc("POST /macs/{id}/delete", app.macDelete)
	mux.HandleFunc("GET /audit", app.auditIndex)

	mux.HandleFunc("GET /scans", app.scansIndex)
	mux.HandleFunc("GET /scans/new", app.scanNew)
	mux.HandleFunc("POST /scans", app.scanCreate)
	mux.HandleFunc("GET /scans/{id}", app.scanShow)

	mux.HandleFunc("GET /agents", app.agentsIndex)
	mux.HandleFunc("GET /agents/new", app.agentNew)
	mux.HandleFunc("POST /agents", app.agentCreate)
	mux.HandleFunc("POST /agents/discover", app.agentDiscover)
	mux.HandleFunc("GET /agents/{id}/edit", app.agentEdit)
	mux.HandleFunc("POST /agents/{id}", app.agentUpdate)
	mux.HandleFunc("POST /agents/{id}/approve", app.agentApprove)
	mux.HandleFunc("GET /agents/{id}/delete", app.agentDeleteConfirm)
	mux.HandleFunc("POST /agents/{id}/delete", app.agentDelete)

	mux.HandleFunc("GET /discoveries", app.discoveriesIndex)
	mux.HandleFunc("POST /discoveries/{id}/import", app.discoveryImport)
	mux.HandleFunc("POST /discoveries/{id}/dismiss", app.discoveryDismiss)

	mux.HandleFunc("GET /schedules", app.schedulesIndex)
	mux.HandleFunc("GET /schedules/new", app.scheduleNew)
	mux.HandleFunc("POST /schedules", app.scheduleCreate)
	mux.HandleFunc("GET /schedules/{id}/edit", app.scheduleEdit)
	mux.HandleFunc("POST /schedules/{id}", app.scheduleUpdate)
	mux.HandleFunc("POST /schedules/{id}/run", app.scheduleRunNow)
	mux.HandleFunc("GET /schedules/{id}/delete", app.scheduleDeleteConfirm)
	mux.HandleFunc("POST /schedules/{id}/delete", app.scheduleDelete)

	return securityHeaders(mux)
}

func (a *App) health(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"status":"ok","service":"light-ipam"}`))
}

func (a *App) dashboard(w http.ResponseWriter, r *http.Request) {
	if a.needsBootstrap(r) {
		http.Redirect(w, r, "/bootstrap", http.StatusSeeOther)
		return
	}

	session, ok := a.requireSession(w, r)
	if !ok {
		return
	}
	stats, err := a.store.DashboardStats(r.Context())
	if err != nil {
		a.logger.Error("dashboard stats", "error", err)
		http.Error(w, "Unable to load dashboard", http.StatusInternalServerError)
		return
	}
	subnets, err := a.store.ListSubnets(r.Context())
	if err != nil {
		a.logger.Error("list subnets", "error", err)
		http.Error(w, "Unable to load dashboard", http.StatusInternalServerError)
		return
	}
	devices, err := a.store.ListDevices(r.Context())
	if err != nil {
		a.logger.Error("list devices", "error", err)
		http.Error(w, "Unable to load dashboard", http.StatusInternalServerError)
		return
	}
	auditLogs, err := a.store.ListAuditLogs(r.Context(), store.AuditFilters{Limit: 5})
	if err != nil {
		a.logger.Error("list audit logs", "error", err)
		http.Error(w, "Unable to load dashboard", http.StatusInternalServerError)
		return
	}
	pendingDiscovery, err := a.store.CountPendingDiscoveries(r.Context())
	if err != nil {
		a.logger.Error("count pending discoveries", "error", err)
	}
	recentScans, err := a.store.ListScanJobs(r.Context(), 4)
	if err != nil {
		a.logger.Error("list scan jobs", "error", err)
	}

	_ = ui.Render(w, "dashboard.html", ui.PageData{
		Title:            "Dashboard",
		User:             session.User,
		CSRF:             session.CSRFToken,
		Stats:            stats,
		Subnets:          subnets,
		Devices:          devices,
		AuditLogs:        auditLogs,
		PendingDiscovery: pendingDiscovery,
		ScanJobs:         recentScans,
		ActiveNav:        "dashboard",
	})
}

func (a *App) search(w http.ResponseWriter, r *http.Request) {
	session, ok := a.requireSession(w, r)
	if !ok {
		return
	}
	query := strings.TrimSpace(r.URL.Query().Get("q"))
	var results store.SearchResults
	if query != "" {
		var err error
		results, err = a.store.Search(r.Context(), query)
		if err != nil {
			a.logger.Error("search", "error", err)
			http.Error(w, "Unable to run search", http.StatusInternalServerError)
			return
		}
	}
	_ = ui.Render(w, "search.html", ui.PageData{
		Title:         "Search",
		User:          session.User,
		CSRF:          session.CSRFToken,
		SearchQuery:   query,
		SearchResults: results,
		ActiveNav:     "search",
	})
}

func (a *App) auditIndex(w http.ResponseWriter, r *http.Request) {
	session, ok := a.requireSession(w, r)
	if !ok {
		return
	}
	filters := store.AuditFilters{
		Action:      strings.TrimSpace(r.URL.Query().Get("action")),
		SubjectType: strings.TrimSpace(r.URL.Query().Get("subject_type")),
		ActorUserID: strings.TrimSpace(r.URL.Query().Get("actor")),
		Limit:       100,
	}
	logs, err := a.store.ListAuditLogs(r.Context(), filters)
	if err != nil {
		a.logger.Error("list audit logs", "error", err)
		http.Error(w, "Unable to load audit logs", http.StatusInternalServerError)
		return
	}
	actions, err := a.store.AuditActions(r.Context())
	if err != nil {
		a.logger.Error("list audit actions", "error", err)
		http.Error(w, "Unable to load audit filters", http.StatusInternalServerError)
		return
	}
	subjects, err := a.store.AuditSubjectTypes(r.Context())
	if err != nil {
		a.logger.Error("list audit subjects", "error", err)
		http.Error(w, "Unable to load audit filters", http.StatusInternalServerError)
		return
	}
	actors, err := a.store.AuditActors(r.Context())
	if err != nil {
		a.logger.Error("list audit actors", "error", err)
		http.Error(w, "Unable to load audit filters", http.StatusInternalServerError)
		return
	}
	_ = ui.Render(w, "audit.html", ui.PageData{
		Title:         "Audit Log",
		User:          session.User,
		CSRF:          session.CSRFToken,
		AuditLogs:     logs,
		AuditActions:  actions,
		AuditSubjects: subjects,
		AuditActors:   actors,
		Form: map[string]string{
			"action":       filters.Action,
			"subject_type": filters.SubjectType,
			"actor":        filters.ActorUserID,
		},
		ActiveNav: "audit",
	})
}

func (a *App) subnetsIndex(w http.ResponseWriter, r *http.Request) {
	session, ok := a.requireSession(w, r)
	if !ok {
		return
	}
	subnets, err := a.store.ListSubnets(r.Context())
	if err != nil {
		a.logger.Error("list subnets", "error", err)
		http.Error(w, "Unable to load subnets", http.StatusInternalServerError)
		return
	}
	_ = ui.Render(w, "subnets.html", ui.PageData{
		Title:     "Subnets",
		User:      session.User,
		CSRF:      session.CSRFToken,
		Subnets:   subnets,
		ActiveNav: "subnets",
	})
}

func (a *App) subnetNew(w http.ResponseWriter, r *http.Request) {
	session, ok := a.requireSession(w, r)
	if !ok {
		return
	}
	a.renderSubnetForm(w, r, session, "New Subnet", store.Subnet{}, nil, "")
}

func (a *App) subnetCreate(w http.ResponseWriter, r *http.Request) {
	session, ok := a.requireSession(w, r)
	if !ok {
		return
	}
	if !a.verifySessionCSRF(r, session) {
		http.Error(w, "Invalid form token", http.StatusForbidden)
		return
	}
	input, form, err := subnetInputFromRequest(r)
	if err != nil {
		a.renderSubnetForm(w, r, session, "New Subnet", store.Subnet{}, form, err.Error())
		return
	}
	subnet, err := a.store.CreateSubnet(r.Context(), input)
	if err != nil {
		a.renderSubnetForm(w, r, session, "New Subnet", store.Subnet{}, form, subnetError(err))
		return
	}
	a.audit(r, &session.User.ID, "subnet.created", "subnet", subnet.ID)
	http.Redirect(w, r, "/subnets/"+subnet.ID, http.StatusSeeOther)
}

func (a *App) subnetShow(w http.ResponseWriter, r *http.Request) {
	session, subnet, ok := a.loadSubnetPage(w, r)
	if !ok {
		return
	}
	addresses, err := a.store.ListAddresses(r.Context(), subnet.ID)
	if err != nil {
		a.logger.Error("list addresses", "error", err)
		http.Error(w, "Unable to load addresses", http.StatusInternalServerError)
		return
	}
	devices, err := a.store.ListDevices(r.Context())
	if err != nil {
		a.logger.Error("list devices", "error", err)
		http.Error(w, "Unable to load devices", http.StatusInternalServerError)
		return
	}
	_ = ui.Render(w, "subnet_detail.html", ui.PageData{
		Title:         subnet.Name,
		User:          session.User,
		CSRF:          session.CSRFToken,
		Subnet:        subnet,
		Addresses:     addresses,
		AddressStates: addressStates(),
		Devices:       devices,
		ActiveNav:     "subnets",
	})
}

func (a *App) subnetEdit(w http.ResponseWriter, r *http.Request) {
	session, subnet, ok := a.loadSubnetPage(w, r)
	if !ok {
		return
	}
	a.renderSubnetForm(w, r, session, "Edit Subnet", subnet, subnetFormFromSubnet(subnet), "")
}

func (a *App) subnetUpdate(w http.ResponseWriter, r *http.Request) {
	session, subnet, ok := a.loadSubnetPage(w, r)
	if !ok {
		return
	}
	if !a.verifySessionCSRF(r, session) {
		http.Error(w, "Invalid form token", http.StatusForbidden)
		return
	}
	input, form, err := subnetInputFromRequest(r)
	if err != nil {
		a.renderSubnetForm(w, r, session, "Edit Subnet", subnet, form, err.Error())
		return
	}
	updated, err := a.store.UpdateSubnet(r.Context(), subnet.ID, input)
	if err != nil {
		a.renderSubnetForm(w, r, session, "Edit Subnet", subnet, form, subnetError(err))
		return
	}
	a.audit(r, &session.User.ID, "subnet.updated", "subnet", updated.ID)
	http.Redirect(w, r, "/subnets/"+updated.ID, http.StatusSeeOther)
}

func (a *App) subnetDelete(w http.ResponseWriter, r *http.Request) {
	session, subnet, ok := a.loadSubnetPage(w, r)
	if !ok {
		return
	}
	if !a.verifySessionCSRF(r, session) {
		http.Error(w, "Invalid form token", http.StatusForbidden)
		return
	}
	if err := a.store.DeleteSubnet(r.Context(), subnet.ID); err != nil {
		a.logger.Error("delete subnet", "error", err)
		http.Error(w, "Unable to delete subnet", http.StatusInternalServerError)
		return
	}
	a.audit(r, &session.User.ID, "subnet.deleted", "subnet", subnet.ID)
	http.Redirect(w, r, "/subnets", http.StatusSeeOther)
}

func (a *App) subnetDeleteConfirm(w http.ResponseWriter, r *http.Request) {
	session, subnet, ok := a.loadSubnetPage(w, r)
	if !ok {
		return
	}
	_ = ui.Render(w, "confirm.html", ui.PageData{
		Title:     "Delete Subnet",
		User:      session.User,
		CSRF:      session.CSRFToken,
		ActiveNav: "subnets",
		Form: map[string]string{
			"heading":      "Delete subnet",
			"message":      "This removes the subnet and detaches any touched address records from it.",
			"subject":      subnet.Name + " (" + subnet.CIDR + ")",
			"action":       "/subnets/" + subnet.ID + "/delete",
			"cancel":       "/subnets/" + subnet.ID,
			"confirm_text": "Delete subnet",
		},
	})
}

func (a *App) addressCreate(w http.ResponseWriter, r *http.Request) {
	session, subnet, ok := a.loadSubnetPage(w, r)
	if !ok {
		return
	}
	if !a.verifySessionCSRF(r, session) {
		http.Error(w, "Invalid form token", http.StatusForbidden)
		return
	}
	input, err := addressInputFromRequest(r)
	if err != nil {
		a.renderSubnetDetailError(w, r, session, subnet, err.Error())
		return
	}
	address, err := a.store.CreateAddress(r.Context(), subnet, input)
	if err != nil {
		a.renderSubnetDetailError(w, r, session, subnet, addressError(err))
		return
	}
	a.audit(r, &session.User.ID, "address.created", "ip_address", address.ID)
	http.Redirect(w, r, "/subnets/"+subnet.ID, http.StatusSeeOther)
}

func (a *App) addressEdit(w http.ResponseWriter, r *http.Request) {
	session, address, subnet, ok := a.loadAddressPage(w, r)
	if !ok {
		return
	}
	a.renderAddressForm(w, r, session, "Edit Address", subnet, address, addressFormFromAddress(address), "")
}

func (a *App) addressUpdate(w http.ResponseWriter, r *http.Request) {
	session, address, subnet, ok := a.loadAddressPage(w, r)
	if !ok {
		return
	}
	if !a.verifySessionCSRF(r, session) {
		http.Error(w, "Invalid form token", http.StatusForbidden)
		return
	}
	input, err := addressInputFromRequest(r)
	if err != nil {
		a.renderAddressForm(w, r, session, "Edit Address", subnet, address, addressFormFromInput(input), err.Error())
		return
	}
	updated, err := a.store.UpdateAddress(r.Context(), address.ID, subnet, input)
	if err != nil {
		a.renderAddressForm(w, r, session, "Edit Address", subnet, address, addressFormFromInput(input), addressError(err))
		return
	}
	a.audit(r, &session.User.ID, "address.updated", "ip_address", updated.ID)
	http.Redirect(w, r, "/subnets/"+subnet.ID, http.StatusSeeOther)
}

func (a *App) addressDeleteConfirm(w http.ResponseWriter, r *http.Request) {
	session, address, subnet, ok := a.loadAddressPage(w, r)
	if !ok {
		return
	}
	_ = ui.Render(w, "confirm.html", ui.PageData{
		Title:     "Remove Address",
		User:      session.User,
		CSRF:      session.CSRFToken,
		ActiveNav: "subnets",
		Form: map[string]string{
			"heading":      "Remove address",
			"message":      "This removes the sparse address record. The address can still be recreated later.",
			"subject":      address.Address + " in " + subnet.Name,
			"action":       "/addresses/" + address.ID + "/delete",
			"cancel":       "/subnets/" + subnet.ID,
			"confirm_text": "Remove address",
			"subnet_id":    subnet.ID,
		},
	})
}

func (a *App) addressDelete(w http.ResponseWriter, r *http.Request) {
	session, ok := a.requireSession(w, r)
	if !ok {
		return
	}
	if !a.verifySessionCSRF(r, session) {
		http.Error(w, "Invalid form token", http.StatusForbidden)
		return
	}
	addressID := r.PathValue("id")
	subnetID := strings.TrimSpace(r.FormValue("subnet_id"))
	if err := a.store.DeleteAddress(r.Context(), addressID); err != nil {
		a.logger.Error("delete address", "error", err)
		http.Error(w, "Unable to delete address", http.StatusInternalServerError)
		return
	}
	a.audit(r, &session.User.ID, "address.deleted", "ip_address", addressID)
	if subnetID == "" {
		http.Redirect(w, r, "/subnets", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/subnets/"+subnetID, http.StatusSeeOther)
}

func (a *App) devicesIndex(w http.ResponseWriter, r *http.Request) {
	session, ok := a.requireSession(w, r)
	if !ok {
		return
	}
	groups, err := a.store.ListDeviceGroups(r.Context())
	if err != nil {
		a.logger.Error("list device groups", "error", err)
		http.Error(w, "Unable to load devices", http.StatusInternalServerError)
		return
	}
	_ = ui.Render(w, "devices.html", ui.PageData{
		Title:        "Devices",
		User:         session.User,
		CSRF:         session.CSRFToken,
		DeviceGroups: groups,
		ActiveNav:    "devices",
	})
}

func (a *App) deviceNew(w http.ResponseWriter, r *http.Request) {
	session, ok := a.requireSession(w, r)
	if !ok {
		return
	}
	a.renderDeviceForm(w, session, "New Device", store.Device{}, nil, "")
}

func (a *App) deviceCreate(w http.ResponseWriter, r *http.Request) {
	session, ok := a.requireSession(w, r)
	if !ok {
		return
	}
	if !a.verifySessionCSRF(r, session) {
		http.Error(w, "Invalid form token", http.StatusForbidden)
		return
	}
	input, form, err := deviceInputFromRequest(r)
	if err != nil {
		a.renderDeviceForm(w, session, "New Device", store.Device{}, form, err.Error())
		return
	}
	device, err := a.store.CreateDevice(r.Context(), input)
	if err != nil {
		a.renderDeviceForm(w, session, "New Device", store.Device{}, form, "Unable to create device.")
		return
	}
	a.audit(r, &session.User.ID, "device.created", "device", device.ID)
	http.Redirect(w, r, "/devices/"+device.ID, http.StatusSeeOther)
}

func (a *App) deviceShow(w http.ResponseWriter, r *http.Request) {
	session, device, ok := a.loadDevicePage(w, r)
	if !ok {
		return
	}
	macs, err := a.store.ListMACAddresses(r.Context(), device.ID)
	if err != nil {
		a.logger.Error("list macs", "error", err)
		http.Error(w, "Unable to load MAC addresses", http.StatusInternalServerError)
		return
	}
	addresses, err := a.store.ListDeviceIPAddresses(r.Context(), device.ID)
	if err != nil {
		a.logger.Error("list device addresses", "error", err)
		http.Error(w, "Unable to load addresses", http.StatusInternalServerError)
		return
	}
	_ = ui.Render(w, "device_detail.html", ui.PageData{
		Title:        device.Name,
		User:         session.User,
		CSRF:         session.CSRFToken,
		Device:       device,
		MACAddresses: macs,
		Addresses:    addresses,
		ActiveNav:    "devices",
	})
}

func (a *App) deviceEdit(w http.ResponseWriter, r *http.Request) {
	session, device, ok := a.loadDevicePage(w, r)
	if !ok {
		return
	}
	a.renderDeviceForm(w, session, "Edit Device", device, deviceFormFromDevice(device), "")
}

func (a *App) deviceUpdate(w http.ResponseWriter, r *http.Request) {
	session, device, ok := a.loadDevicePage(w, r)
	if !ok {
		return
	}
	if !a.verifySessionCSRF(r, session) {
		http.Error(w, "Invalid form token", http.StatusForbidden)
		return
	}
	input, form, err := deviceInputFromRequest(r)
	if err != nil {
		a.renderDeviceForm(w, session, "Edit Device", device, form, err.Error())
		return
	}
	updated, err := a.store.UpdateDevice(r.Context(), device.ID, input)
	if err != nil {
		a.renderDeviceForm(w, session, "Edit Device", device, form, "Unable to update device.")
		return
	}
	a.audit(r, &session.User.ID, "device.updated", "device", updated.ID)
	http.Redirect(w, r, "/devices/"+updated.ID, http.StatusSeeOther)
}

func (a *App) deviceDelete(w http.ResponseWriter, r *http.Request) {
	session, device, ok := a.loadDevicePage(w, r)
	if !ok {
		return
	}
	if !a.verifySessionCSRF(r, session) {
		http.Error(w, "Invalid form token", http.StatusForbidden)
		return
	}
	if err := a.store.DeleteDevice(r.Context(), device.ID); err != nil {
		a.logger.Error("delete device", "error", err)
		http.Error(w, "Unable to delete device", http.StatusInternalServerError)
		return
	}
	a.audit(r, &session.User.ID, "device.deleted", "device", device.ID)
	http.Redirect(w, r, "/devices", http.StatusSeeOther)
}

func (a *App) deviceDeleteConfirm(w http.ResponseWriter, r *http.Request) {
	session, device, ok := a.loadDevicePage(w, r)
	if !ok {
		return
	}
	_ = ui.Render(w, "confirm.html", ui.PageData{
		Title:     "Delete Device",
		User:      session.User,
		CSRF:      session.CSRFToken,
		ActiveNav: "devices",
		Form: map[string]string{
			"heading":      "Delete device",
			"message":      "This deletes the device, removes its MAC addresses, and leaves linked IP records unassigned.",
			"subject":      device.Name,
			"action":       "/devices/" + device.ID + "/delete",
			"cancel":       "/devices/" + device.ID,
			"confirm_text": "Delete device",
		},
	})
}

func (a *App) macCreate(w http.ResponseWriter, r *http.Request) {
	session, device, ok := a.loadDevicePage(w, r)
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
	mac, err := a.store.CreateMACAddress(r.Context(), device.ID, strings.TrimSpace(r.FormValue("address")))
	if err != nil {
		a.renderDeviceDetailError(w, r, session, device, "Enter a valid, unique MAC address.")
		return
	}
	a.audit(r, &session.User.ID, "mac.created", "mac_address", mac.ID)
	http.Redirect(w, r, "/devices/"+device.ID, http.StatusSeeOther)
}

func (a *App) macDelete(w http.ResponseWriter, r *http.Request) {
	session, ok := a.requireSession(w, r)
	if !ok {
		return
	}
	if !a.verifySessionCSRF(r, session) {
		http.Error(w, "Invalid form token", http.StatusForbidden)
		return
	}
	macID := r.PathValue("id")
	deviceID := strings.TrimSpace(r.FormValue("device_id"))
	if err := a.store.DeleteMACAddress(r.Context(), macID); err != nil {
		a.logger.Error("delete mac", "error", err)
		http.Error(w, "Unable to delete MAC address", http.StatusInternalServerError)
		return
	}
	a.audit(r, &session.User.ID, "mac.deleted", "mac_address", macID)
	if deviceID == "" {
		http.Redirect(w, r, "/devices", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/devices/"+deviceID, http.StatusSeeOther)
}

func (a *App) macDeleteConfirm(w http.ResponseWriter, r *http.Request) {
	session, ok := a.requireSession(w, r)
	if !ok {
		return
	}
	mac, err := a.store.GetMACAddress(r.Context(), r.PathValue("id"))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			http.NotFound(w, r)
			return
		}
		a.logger.Error("get mac", "error", err)
		http.Error(w, "Unable to load MAC address", http.StatusInternalServerError)
		return
	}
	_ = ui.Render(w, "confirm.html", ui.PageData{
		Title:     "Remove MAC",
		User:      session.User,
		CSRF:      session.CSRFToken,
		ActiveNav: "devices",
		Form: map[string]string{
			"heading":      "Remove MAC address",
			"message":      "This removes the MAC address record from the device.",
			"subject":      mac.Address,
			"action":       "/macs/" + mac.ID + "/delete",
			"cancel":       "/devices/" + mac.DeviceID,
			"confirm_text": "Remove MAC",
			"device_id":    mac.DeviceID,
		},
	})
}

func (a *App) bootstrapForm(w http.ResponseWriter, r *http.Request) {
	if !a.needsBootstrap(r) {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	csrf, err := auth.RandomToken(32)
	if err != nil {
		http.Error(w, "Unable to create form token", http.StatusInternalServerError)
		return
	}
	a.setCSRFCookie(w, csrf)
	_ = ui.Render(w, "bootstrap.html", ui.PageData{
		Title: "Create Admin",
		CSRF:  csrf,
	})
}

func (a *App) bootstrapSubmit(w http.ResponseWriter, r *http.Request) {
	if !a.needsBootstrap(r) {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if !a.verifyFormCSRF(r) {
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
	if displayName == "" {
		displayName = username
	}
	if username == "" || len(password) < 12 {
		a.renderBootstrapError(w, "Use a username and a password with at least 12 characters.")
		return
	}

	passwordHash, err := auth.HashPassword(password)
	if err != nil {
		http.Error(w, "Unable to secure password", http.StatusInternalServerError)
		return
	}

	user, err := a.store.CreateAdmin(r.Context(), username, displayName, passwordHash)
	if err != nil {
		a.logger.Error("create bootstrap admin", "error", err)
		a.renderBootstrapError(w, "Unable to create the admin account. Try a different username.")
		return
	}

	if err := a.store.CreateAuditLog(r.Context(), &user.ID, "admin.bootstrap.created", "user", user.ID, "{}"); err != nil {
		a.logger.Error("create audit log", "error", err)
	}

	a.establishSession(w, r, user.ID)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (a *App) loginForm(w http.ResponseWriter, r *http.Request) {
	if a.needsBootstrap(r) {
		http.Redirect(w, r, "/bootstrap", http.StatusSeeOther)
		return
	}
	csrf, err := auth.RandomToken(32)
	if err != nil {
		http.Error(w, "Unable to create form token", http.StatusInternalServerError)
		return
	}
	a.setCSRFCookie(w, csrf)
	_ = ui.Render(w, "login.html", ui.PageData{
		Title: "Sign In",
		CSRF:  csrf,
	})
}

func (a *App) loginSubmit(w http.ResponseWriter, r *http.Request) {
	if !a.verifyFormCSRF(r) {
		http.Error(w, "Invalid form token", http.StatusForbidden)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form", http.StatusBadRequest)
		return
	}

	username := strings.TrimSpace(r.FormValue("username"))
	password := r.FormValue("password")
	user, err := a.store.FindUserByUsername(r.Context(), username)
	if err != nil || !auth.VerifyPassword(user.PasswordHash, password) {
		_ = ui.Render(w, "login.html", ui.PageData{
			Title: "Sign In",
			Error: "The username or password is incorrect.",
			CSRF:  r.FormValue("csrf_token"),
		})
		return
	}

	if err := a.store.CreateAuditLog(r.Context(), &user.ID, "auth.login", "user", user.ID, "{}"); err != nil {
		a.logger.Error("create audit log", "error", err)
	}

	a.establishSession(w, r, user.ID)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (a *App) logout(w http.ResponseWriter, r *http.Request) {
	session, ok := a.currentSession(r)
	if ok && r.FormValue("csrf_token") == session.CSRFToken {
		if err := a.store.DeleteSession(r.Context(), session.ID); err != nil {
			a.logger.Error("delete session", "error", err)
		}
		if err := a.store.CreateAuditLog(r.Context(), &session.User.ID, "auth.logout", "user", session.User.ID, "{}"); err != nil {
			a.logger.Error("create audit log", "error", err)
		}
	}
	a.clearSessionCookie(w)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (a *App) needsBootstrap(r *http.Request) bool {
	count, err := a.store.CountAdmins(r.Context())
	if err != nil {
		a.logger.Error("count admins", "error", err)
		return false
	}
	return count == 0
}

func (a *App) requireSession(w http.ResponseWriter, r *http.Request) (store.Session, bool) {
	session, ok := a.currentSession(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return store.Session{}, false
	}
	return session, true
}

func (a *App) currentSession(r *http.Request) (store.Session, bool) {
	cookie, err := r.Cookie(sessionCookie)
	if err != nil || cookie.Value == "" {
		return store.Session{}, false
	}
	session, err := a.store.GetSession(r.Context(), cookie.Value)
	if err != nil {
		if !errors.Is(err, store.ErrNotFound) {
			a.logger.Error("get session", "error", err)
		}
		return store.Session{}, false
	}
	return session, true
}

func (a *App) establishSession(w http.ResponseWriter, r *http.Request, userID string) {
	expiresAt := time.Now().Add(12 * time.Hour)
	session, err := a.store.CreateSession(r.Context(), userID, expiresAt)
	if err != nil {
		a.logger.Error("create session", "error", err)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    session.ID,
		Path:     "/",
		Expires:  expiresAt,
		HttpOnly: true,
		Secure:   a.cfg.CookieSecure,
		SameSite: http.SameSiteLaxMode,
	})
}

func (a *App) setCSRFCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     csrfCookie,
		Value:    token,
		Path:     "/",
		MaxAge:   600,
		HttpOnly: true,
		Secure:   a.cfg.CookieSecure,
		SameSite: http.SameSiteLaxMode,
	})
}

func (a *App) clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   a.cfg.CookieSecure,
		SameSite: http.SameSiteLaxMode,
	})
}

func (a *App) verifyFormCSRF(r *http.Request) bool {
	cookie, err := r.Cookie(csrfCookie)
	if err != nil {
		return false
	}
	return cookie.Value != "" && cookie.Value == r.FormValue("csrf_token")
}

func (a *App) renderBootstrapError(w http.ResponseWriter, message string) {
	csrf, _ := auth.RandomToken(32)
	a.setCSRFCookie(w, csrf)
	_ = ui.Render(w, "bootstrap.html", ui.PageData{
		Title: "Create Admin",
		Error: message,
		CSRF:  csrf,
	})
}

func (a *App) renderSubnetForm(w http.ResponseWriter, r *http.Request, session store.Session, title string, subnet store.Subnet, form map[string]string, message string) {
	sites, err := a.store.ListSites(r.Context())
	if err != nil {
		a.logger.Error("list sites", "error", err)
		http.Error(w, "Unable to load form", http.StatusInternalServerError)
		return
	}
	if form == nil {
		form = map[string]string{"site_id": "default"}
	}
	_ = ui.Render(w, "subnet_form.html", ui.PageData{
		Title:     title,
		Error:     message,
		User:      session.User,
		CSRF:      session.CSRFToken,
		Sites:     sites,
		Subnet:    subnet,
		Form:      form,
		ActiveNav: "subnets",
	})
}

func (a *App) renderSubnetDetailError(w http.ResponseWriter, r *http.Request, session store.Session, subnet store.Subnet, message string) {
	addresses, err := a.store.ListAddresses(r.Context(), subnet.ID)
	if err != nil {
		a.logger.Error("list addresses", "error", err)
		http.Error(w, "Unable to load addresses", http.StatusInternalServerError)
		return
	}
	devices, err := a.store.ListDevices(r.Context())
	if err != nil {
		a.logger.Error("list devices", "error", err)
		http.Error(w, "Unable to load devices", http.StatusInternalServerError)
		return
	}
	_ = ui.Render(w, "subnet_detail.html", ui.PageData{
		Title:         subnet.Name,
		Error:         message,
		User:          session.User,
		CSRF:          session.CSRFToken,
		Subnet:        subnet,
		Addresses:     addresses,
		AddressStates: addressStates(),
		Devices:       devices,
		ActiveNav:     "subnets",
	})
}

func (a *App) renderAddressForm(w http.ResponseWriter, r *http.Request, session store.Session, title string, subnet store.Subnet, address store.IPAddress, form map[string]string, message string) {
	devices, err := a.store.ListDevices(r.Context())
	if err != nil {
		a.logger.Error("list devices", "error", err)
		http.Error(w, "Unable to load devices", http.StatusInternalServerError)
		return
	}
	if form == nil {
		form = map[string]string{}
	}
	_ = ui.Render(w, "address_form.html", ui.PageData{
		Title:         title,
		Error:         message,
		User:          session.User,
		CSRF:          session.CSRFToken,
		Subnet:        subnet,
		Address:       address,
		AddressStates: addressStates(),
		Devices:       devices,
		Form:          form,
		ActiveNav:     "subnets",
	})
}

func (a *App) renderDeviceForm(w http.ResponseWriter, session store.Session, title string, device store.Device, form map[string]string, message string) {
	if form == nil {
		form = map[string]string{}
	}
	_ = ui.Render(w, "device_form.html", ui.PageData{
		Title:     title,
		Error:     message,
		User:      session.User,
		CSRF:      session.CSRFToken,
		Device:    device,
		Form:      form,
		ActiveNav: "devices",
	})
}

func (a *App) renderDeviceDetailError(w http.ResponseWriter, r *http.Request, session store.Session, device store.Device, message string) {
	macs, err := a.store.ListMACAddresses(r.Context(), device.ID)
	if err != nil {
		a.logger.Error("list macs", "error", err)
		http.Error(w, "Unable to load MAC addresses", http.StatusInternalServerError)
		return
	}
	addresses, err := a.store.ListDeviceIPAddresses(r.Context(), device.ID)
	if err != nil {
		a.logger.Error("list device addresses", "error", err)
		http.Error(w, "Unable to load addresses", http.StatusInternalServerError)
		return
	}
	_ = ui.Render(w, "device_detail.html", ui.PageData{
		Title:        device.Name,
		Error:        message,
		User:         session.User,
		CSRF:         session.CSRFToken,
		Device:       device,
		MACAddresses: macs,
		Addresses:    addresses,
		ActiveNav:    "devices",
	})
}

func (a *App) loadSubnetPage(w http.ResponseWriter, r *http.Request) (store.Session, store.Subnet, bool) {
	session, ok := a.requireSession(w, r)
	if !ok {
		return store.Session{}, store.Subnet{}, false
	}
	subnet, err := a.store.GetSubnet(r.Context(), r.PathValue("id"))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			http.NotFound(w, r)
			return store.Session{}, store.Subnet{}, false
		}
		a.logger.Error("get subnet", "error", err)
		http.Error(w, "Unable to load subnet", http.StatusInternalServerError)
		return store.Session{}, store.Subnet{}, false
	}
	return session, subnet, true
}

func (a *App) loadAddressPage(w http.ResponseWriter, r *http.Request) (store.Session, store.IPAddress, store.Subnet, bool) {
	session, ok := a.requireSession(w, r)
	if !ok {
		return store.Session{}, store.IPAddress{}, store.Subnet{}, false
	}
	address, err := a.store.GetAddress(r.Context(), r.PathValue("id"))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			http.NotFound(w, r)
			return store.Session{}, store.IPAddress{}, store.Subnet{}, false
		}
		a.logger.Error("get address", "error", err)
		http.Error(w, "Unable to load address", http.StatusInternalServerError)
		return store.Session{}, store.IPAddress{}, store.Subnet{}, false
	}
	subnet, err := a.store.GetSubnet(r.Context(), address.SubnetID)
	if err != nil {
		a.logger.Error("get address subnet", "error", err)
		http.Error(w, "Unable to load subnet", http.StatusInternalServerError)
		return store.Session{}, store.IPAddress{}, store.Subnet{}, false
	}
	return session, address, subnet, true
}

func (a *App) loadDevicePage(w http.ResponseWriter, r *http.Request) (store.Session, store.Device, bool) {
	session, ok := a.requireSession(w, r)
	if !ok {
		return store.Session{}, store.Device{}, false
	}
	device, err := a.store.GetDevice(r.Context(), r.PathValue("id"))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			http.NotFound(w, r)
			return store.Session{}, store.Device{}, false
		}
		a.logger.Error("get device", "error", err)
		http.Error(w, "Unable to load device", http.StatusInternalServerError)
		return store.Session{}, store.Device{}, false
	}
	return session, device, true
}

func (a *App) verifySessionCSRF(r *http.Request, session store.Session) bool {
	return session.CSRFToken != "" && session.CSRFToken == r.FormValue("csrf_token")
}

func (a *App) audit(r *http.Request, actorUserID *string, action, subjectType, subjectID string) {
	if err := a.store.CreateAuditLog(r.Context(), actorUserID, action, subjectType, subjectID, "{}"); err != nil {
		a.logger.Error("create audit log", "error", err, "action", action)
	}
}

func subnetInputFromRequest(r *http.Request) (store.SubnetInput, map[string]string, error) {
	if err := r.ParseForm(); err != nil {
		return store.SubnetInput{}, nil, err
	}
	form := map[string]string{
		"site_id":     strings.TrimSpace(r.FormValue("site_id")),
		"name":        strings.TrimSpace(r.FormValue("name")),
		"cidr":        strings.TrimSpace(r.FormValue("cidr")),
		"vlan":        strings.TrimSpace(r.FormValue("vlan")),
		"description": strings.TrimSpace(r.FormValue("description")),
	}
	if form["name"] == "" {
		return store.SubnetInput{}, form, errors.New("Subnet name is required.")
	}
	cidr, err := ipam.NormalizeCIDR(form["cidr"])
	if err != nil {
		return store.SubnetInput{}, form, errors.New("Enter a valid IPv4 CIDR such as 192.168.10.0/24.")
	}
	vlan, err := store.ParseVLAN(form["vlan"])
	if err != nil {
		return store.SubnetInput{}, form, err
	}
	form["cidr"] = cidr
	return store.SubnetInput{
		SiteID:      form["site_id"],
		Name:        form["name"],
		CIDR:        cidr,
		VLAN:        vlan,
		Description: form["description"],
	}, form, nil
}

func subnetFormFromSubnet(subnet store.Subnet) map[string]string {
	form := map[string]string{
		"site_id":     subnet.SiteID,
		"name":        subnet.Name,
		"cidr":        subnet.CIDR,
		"description": subnet.Description,
	}
	if subnet.VLAN != nil {
		form["vlan"] = intString(*subnet.VLAN)
	}
	return form
}

func addressInputFromRequest(r *http.Request) (store.AddressInput, error) {
	if err := r.ParseForm(); err != nil {
		return store.AddressInput{}, err
	}
	address, err := ipam.NormalizeIPv4(strings.TrimSpace(r.FormValue("address")))
	if err != nil {
		return store.AddressInput{}, errors.New("Enter a valid IPv4 address.")
	}
	state := strings.TrimSpace(r.FormValue("state"))
	if !validAddressState(state) {
		return store.AddressInput{}, errors.New("Choose a valid address state.")
	}
	return store.AddressInput{
		Address:  address,
		State:    state,
		DeviceID: strings.TrimSpace(r.FormValue("device_id")),
		Hostname: strings.TrimSpace(r.FormValue("hostname")),
		Notes:    strings.TrimSpace(r.FormValue("notes")),
	}, nil
}

func addressFormFromAddress(address store.IPAddress) map[string]string {
	return map[string]string{
		"address":   address.Address,
		"state":     address.State,
		"device_id": address.DeviceID,
		"hostname":  address.Hostname,
		"notes":     address.Notes,
	}
}

func addressFormFromInput(input store.AddressInput) map[string]string {
	return map[string]string{
		"address":   input.Address,
		"state":     input.State,
		"device_id": input.DeviceID,
		"hostname":  input.Hostname,
		"notes":     input.Notes,
	}
}

func deviceInputFromRequest(r *http.Request) (store.DeviceInput, map[string]string, error) {
	if err := r.ParseForm(); err != nil {
		return store.DeviceInput{}, nil, err
	}
	form := map[string]string{
		"name":        strings.TrimSpace(r.FormValue("name")),
		"description": strings.TrimSpace(r.FormValue("description")),
	}
	if form["name"] == "" {
		return store.DeviceInput{}, form, errors.New("Device name is required.")
	}
	return store.DeviceInput{Name: form["name"], Description: form["description"]}, form, nil
}

func deviceFormFromDevice(device store.Device) map[string]string {
	return map[string]string{
		"name":        device.Name,
		"description": device.Description,
	}
}

func subnetError(err error) string {
	if errors.Is(err, store.ErrOverlap) {
		return "That subnet overlaps an existing subnet. Overlapping subnets are globally blocked."
	}
	if errors.Is(err, store.ErrNotFound) {
		return "That subnet could not be found."
	}
	return "Unable to save subnet."
}

func addressError(err error) string {
	if errors.Is(err, store.ErrAddressOutOfCIDR) {
		return "That address is outside this subnet."
	}
	return "Unable to save address. Check for duplicates and try again."
}

func addressStates() []string {
	return []string{"available", "reserved", "assigned", "deprecated", "conflict"}
}

func validAddressState(state string) bool {
	for _, allowed := range addressStates() {
		if state == allowed {
			return true
		}
	}
	return false
}

func intString(value int) string {
	return strconv.Itoa(value)
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self'; img-src 'self' data:; form-action 'self'; frame-ancestors 'none'")
		w.Header().Set("Referrer-Policy", "same-origin")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		next.ServeHTTP(w, r)
	})
}
