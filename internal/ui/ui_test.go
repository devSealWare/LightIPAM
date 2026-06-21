package ui

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/devSealWare/LightIPAM/internal/backup"
	"github.com/devSealWare/LightIPAM/internal/scanner"
	"github.com/devSealWare/LightIPAM/internal/store"
)

func TestRenderTemplates(t *testing.T) {
	vlan := 20
	data := PageData{
		Title: "Test",
		CSRF:  "token",
		User: store.User{
			ID:          "user-1",
			Username:    "admin",
			DisplayName: "Admin",
			Role:        store.RoleAdmin,
			IsAdmin:     true,
		},
		Stats: store.DashboardStats{
			SubnetCount:   1,
			AddressCount:  1,
			ConflictCount: 0,
		},
		Sites: []store.Site{{ID: "default", Name: "Default"}},
		Subnets: []store.Subnet{{
			ID:             "subnet-1",
			SiteID:         "default",
			SiteName:       "Default",
			CIDR:           "192.168.10.0/24",
			Name:           "Office LAN",
			VLAN:           &vlan,
			Tags:           []string{"core"},
			AddressCount:   1,
			Capacity:       256,
			UtilizationPct: 0.39,
		}},
		Subnet: store.Subnet{
			ID:             "subnet-1",
			SiteID:         "default",
			SiteName:       "Default",
			CIDR:           "192.168.10.0/24",
			Name:           "Office LAN",
			VLAN:           &vlan,
			AddressCount:   1,
			Capacity:       256,
			UtilizationPct: 0.39,
		},
		Addresses: []store.IPAddress{{
			ID:         "address-1",
			SubnetID:   "subnet-1",
			DeviceID:   "device-1",
			DeviceName: "NAS",
			Address:    "192.168.10.20",
			State:      "assigned",
			Hostname:   "nas-1",
			Notes:      "Storage",
			Tags:       []string{"reserved-block"},
			VLAN:       &vlan,
		}},
		AddressStates: []string{"available", "reserved", "assigned", "deprecated", "conflict"},
		Devices: []store.Device{{
			ID:              "device-1",
			Name:            "NAS",
			Description:     "Storage",
			AddressCount:    1,
			MACCount:        1,
			PrivateMACCount: 1,
			Tags:            []string{"Private MAC"},
		}},
		Device: store.Device{
			ID:              "device-1",
			Name:            "NAS",
			Description:     "Storage",
			AddressCount:    1,
			MACCount:        1,
			PrivateMACCount: 1,
			Tags:            []string{"Private MAC"},
		},
		DeviceGroups: []store.DeviceGroup{
			{
				SubnetID:   "subnet-1",
				SubnetName: "Office LAN",
				CIDR:       "192.168.10.0/24",
				Devices: []store.Device{{
					ID:              "device-1",
					Name:            "NAS",
					Description:     "Storage",
					AddressCount:    2,
					PrimaryIP:       "192.168.10.20",
					MACCount:        1,
					PrivateMACCount: 1,
					Tags:            []string{"Private MAC"},
				}},
			},
			{
				Devices: []store.Device{{ID: "device-2", Name: "Unknown host"}},
			},
		},
		MACAddresses: []store.MACAddress{{
			ID:        "mac-1",
			DeviceID:  "device-1",
			Address:   "da:a1:19:22:33:44",
			IsPrivate: true,
		}},
		AuditLogs: []store.AuditLog{{
			ID:               1,
			ActorUserID:      "user-1",
			ActorDisplayName: "Admin",
			Action:           "subnet.created",
			SubjectType:      "subnet",
			SubjectID:        "subnet-1",
			Metadata:         "{}",
		}},
		AuditActions:  []string{"subnet.created"},
		AuditSubjects: []string{"subnet"},
		AuditActors: []store.User{{
			ID:          "user-1",
			Username:    "admin",
			DisplayName: "Admin",
			IsAdmin:     true,
		}},
		ScanAgents: []store.ScanAgent{{
			ID:           "agent-1",
			Name:         "local-scanner-agent",
			EndpointURL:  "https://scanner-agent:8443",
			AllowedCIDRs: []string{"192.168.0.0/16"},
			Status:       "pending",
			Version:      "v1",
		}},
		ScanAgent: store.ScanAgent{
			ID:           "agent-1",
			Name:         "local-scanner-agent",
			EndpointURL:  "https://scanner-agent:8443",
			AllowedCIDRs: []string{"192.168.0.0/16"},
			Status:       "pending",
		},
		ScanJobs: []store.ScanJob{{
			ID:           "job-1",
			AgentName:    "local-scanner-agent",
			ScanType:     "host_discovery",
			Mode:         "light_active",
			Targets:      []string{"192.168.10.0/24"},
			AllowedCIDRs: []string{"192.168.0.0/16"},
			Status:       "succeeded",
		}},
		ScanJob: store.ScanJob{
			ID:           "job-1",
			AgentName:    "local-scanner-agent",
			ScanType:     "host_discovery",
			Mode:         "light_active",
			Targets:      []string{"192.168.10.0/24"},
			AllowedCIDRs: []string{"192.168.0.0/16"},
			Status:       "succeeded",
		},
		ScanSchedules: []store.ScanSchedule{{
			ID:              "sched-1",
			Name:            "Nightly sweep",
			AgentName:       "local-scanner-agent",
			ScanType:        "host_discovery",
			Mode:            "light_active",
			IntervalSeconds: 3600,
			Enabled:         true,
		}},
		ScanSchedule: store.ScanSchedule{
			ID:              "sched-1",
			Name:            "Nightly sweep",
			AgentName:       "local-scanner-agent",
			ScanType:        "host_discovery",
			Mode:            "light_active",
			IntervalSeconds: 3600,
			Enabled:         true,
		},
		ScanObservations: []scanner.Observation{{
			IP:       "192.168.10.42",
			MAC:      "aa:bb:cc:dd:ee:ff",
			Hostname: "printer.local",
			OSFamily: "Linux",
			OSDetail: "Linux 5.x",
			VLAN:     30,
			Services: []scanner.ServiceObservation{{Protocol: "tcp", Port: 9100, State: "open", ServiceName: "jetdirect"}},
			Evidence: []scanner.Evidence{{Source: "snmp", Summary: "VLAN 30 (Printers)"}},
		}},
		ScanTypes: []string{"host_discovery", "service_detection", "os_probe", "combined"},
		ScanTypeGroups: []ScanTypeGroup{
			{Label: "Recommended", Types: []string{"combined"}},
			{Label: "Single-source (advanced)", Types: []string{"arp_table", "snmp_inventory", "name_lookup", "dns_lookup", "dhcp_leases", "lldp_cdp"}},
		},
		ScanModes:     []string{"passive", "light_active", "standard_active", "deep_active"},
		AgentStatuses: []string{"pending", "active", "disabled", "revoked"},
		DispatchReady: true,
		Discoveries: []store.Discovery{{
			ID:              "disc-1",
			IP:              "192.168.10.42",
			MAC:             "aa:bb:cc:dd:ee:ff",
			Vendor:          "Hewlett Packard",
			Hostname:        "printer.local",
			OSFamily:        "Linux",
			OSDetail:        "Linux 5.x",
			Services:        []store.DiscoveryService{{Protocol: "tcp", Port: 9100, State: "open", ServiceName: "jetdirect"}},
			VLAN:            30,
			Status:          "pending",
			ReconcileStatus: "conflict",
			Conflict:        "Address is assigned to NAS with a different MAC",
		}},
		PendingDiscovery:  1,
		ConflictDiscovery: 1,
		ImportResult: store.ImportResult{
			Type:    "subnets",
			Columns: []string{"name", "cidr", "vlan", "site", "description"},
			Created: 1,
			Updated: 1,
			Errors:  1,
			Rows: []store.ImportRow{
				{Line: 2, Cells: []string{"Office LAN", "192.168.10.0/24", "20", "Default", ""}, Action: "create"},
				{Line: 3, Cells: []string{"Bad", "999.0.0.0/24"}, Action: "error", Error: "Enter a valid IPv4 CIDR such as 192.168.10.0/24."},
			},
			CSV: "name,cidr\nOffice LAN,192.168.10.0/24\n",
		},
		Form: map[string]string{
			"site_id":      "default",
			"name":         "Office LAN",
			"cidr":         "192.168.10.0/24",
			"vlan":         "20",
			"description":  "Primary office network",
			"action":       "subnet.created",
			"subject_type": "subnet",
			"actor":        "user-1",
			"heading":      "Confirm",
			"message":      "This is a test confirmation.",
			"subject":      "Office LAN",
			"cancel":       "/",
			"confirm_text": "Confirm",
			// Security tab (settings.html) pre-fill.
			"login_max_attempts":     "5",
			"login_window_minutes":   "15",
			"login_lockout_minutes":  "15",
			"session_idle_minutes":   "30",
			"session_absolute_hours": "12",
			"logout_keeps_current":   "on",
			// Policy tab (settings.html) pre-fill.
			"policy_check_overlaps": "on",
			"policy_check_stale":    "on",
			"policy_check_services": "on",
			"policy_stale_days":     "30",
		},
		Sessions: []store.Session{{
			ID:         "session-1",
			CSRFToken:  "token",
			ClientIP:   "192.168.10.5",
			UserAgent:  "Mozilla/5.0",
			CreatedAt:  time.Now(),
			LastSeenAt: time.Now(),
		}},
		CurrentSessionID: "session-1",
		Users: []store.User{
			{ID: "user-1", Username: "admin", DisplayName: "Admin", Role: store.RoleAdmin, IsAdmin: true, CreatedAt: time.Now()},
			{ID: "user-2", Username: "viewer", DisplayName: "Viewer", Role: store.RoleViewer, CreatedAt: time.Now()},
		},
		CustomFields: []store.CustomFieldValue{
			{Def: store.CustomFieldDef{ID: "cf-1", EntityType: "device", Name: "Owner", FieldType: "text"}, Value: "IT"},
			{Def: store.CustomFieldDef{ID: "cf-2", EntityType: "device", Name: "Asset tag", FieldType: "text"}},
		},
		CustomFieldDefs: []store.CustomFieldDef{
			{ID: "cf-1", EntityType: "device", Name: "Owner", FieldType: "text", CreatedAt: time.Now()},
			{ID: "cf-3", EntityType: "subnet", Name: "Cost center", FieldType: "text", CreatedAt: time.Now()},
		},
		ActiveTab:     "security",
		PolicySummary: store.PolicySummary{Critical: 1, Warning: 2, Info: 1},
		PolicyGroups: []store.PolicyFindingGroup{
			{Check: "overlapping_subnets", Label: "Overlapping subnets", Findings: []store.PolicyFinding{
				{Check: "overlapping_subnets", Severity: store.SeverityCritical, Title: "10.0.0.0/16 overlaps 10.0.5.0/24", Detail: "Overlapping space.", Link: "/subnets/subnet-1"},
			}},
			{Check: "stale_records", Label: "Stale records (not seen in 30 days)", Findings: nil},
		},
		SearchQuery: "192.168",
		SearchResults: store.SearchResults{
			Query:     "192.168",
			Subnets:   []store.SearchResult{{Label: "Office LAN", Detail: "192.168.10.0/24", URL: "/subnets/subnet-1"}},
			Addresses: []store.SearchResult{{Label: "192.168.10.5", Detail: "assigned · printer.local", URL: "/subnets/subnet-1"}},
			Devices:   []store.SearchResult{{Label: "Printer", Detail: "Linux 5.x", URL: "/devices/device-1"}},
			MACs:      []store.SearchResult{{Label: "aa:bb:cc:dd:ee:ff", Detail: "Acme · Printer", URL: "/devices/device-1"}},
			Total:     4,
		},
	}

	for _, name := range []string{
		"bootstrap.html",
		"login.html",
		"dashboard.html",
		"subnets.html",
		"subnet_form.html",
		"subnet_detail.html",
		"devices.html",
		"device_form.html",
		"device_detail.html",
		"audit.html",
		"settings.html",
		"policy.html",
		"forbidden.html",
		"account.html",
		"mfa_challenge.html",
		"mfa_settings.html",
		"address_form.html",
		"confirm.html",
		"scans.html",
		"scan_new.html",
		"scan_detail.html",
		"agents.html",
		"agent_form.html",
		"schedules.html",
		"schedule_form.html",
		"discoveries.html",
		"search.html",
		"import.html",
		"import_preview.html",
	} {
		t.Run(name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			if err := Render(recorder, name, data); err != nil {
				t.Fatalf("render %s: %v", name, err)
			}
			if recorder.Code != 200 {
				t.Fatalf("unexpected status %d", recorder.Code)
			}
		})
	}
}

// TestDashboardWidgetsRenderLiveState guards the dashboard against regressing to
// the static placeholder widgets it shipped with: the "Review queue" must reflect
// the real pending-discovery count and the "Scan status" must list recent jobs
// rather than the stale "planned for Phase 2" copy.
func TestDashboardWidgetsRenderLiveState(t *testing.T) {
	data := PageData{
		Title: "Dashboard",
		User:  store.User{DisplayName: "Admin"},
		ScanJobs: []store.ScanJob{{
			ID:        "job-1",
			AgentName: "local-scanner-agent",
			ScanType:  "combined",
			Status:    "succeeded",
			CreatedAt: time.Now(),
		}},
		PendingDiscovery: 2,
	}

	recorder := httptest.NewRecorder()
	if err := Render(recorder, "dashboard.html", data); err != nil {
		t.Fatalf("render dashboard: %v", err)
	}
	body := recorder.Body.String()

	if strings.Contains(body, "planned for Phase 2") {
		t.Error("dashboard still shows the stale 'planned for Phase 2' scan-status placeholder")
	}
	for _, want := range []string{"awaiting review", "/discoveries", "/scans/job-1", "combined"} {
		if !strings.Contains(body, want) {
			t.Errorf("dashboard missing live-state marker %q", want)
		}
	}
}

// TestSettingsUsersTabRenders guards the Users & Roles settings tab: it must
// render the add-user form and list managed accounts with role controls.
func TestSettingsUsersTabRenders(t *testing.T) {
	data := PageData{
		User:      store.User{ID: "user-1", DisplayName: "Admin", Role: store.RoleAdmin, IsAdmin: true},
		CSRF:      "token",
		ActiveTab: "users",
		Form:      map[string]string{"role": store.RoleViewer},
		Users: []store.User{
			{ID: "user-1", Username: "admin", DisplayName: "Admin", Role: store.RoleAdmin, IsAdmin: true},
			{ID: "user-2", Username: "viewer", DisplayName: "Viewer", Role: store.RoleViewer},
		},
	}
	recorder := httptest.NewRecorder()
	if err := Render(recorder, "settings.html", data); err != nil {
		t.Fatalf("render settings users: %v", err)
	}
	body := recorder.Body.String()
	for _, want := range []string{
		`action="/settings/users"`,
		`action="/settings/users/user-2/role"`,
		`action="/settings/users/user-2/password"`,
		`href="/settings/users/user-2/delete"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("users tab missing %q", want)
		}
	}
	// The acting admin must not get a self-delete link.
	if strings.Contains(body, `href="/settings/users/user-1/delete"`) {
		t.Error("users tab should not offer a self-delete link")
	}
}

// TestSettingsCustomFieldsTabRenders guards the Custom fields settings tab: it
// must render the add-field form and list defined fields with a delete link and
// a friendly entity label.
func TestSettingsCustomFieldsTabRenders(t *testing.T) {
	data := PageData{
		User:      store.User{ID: "user-1", DisplayName: "Admin", Role: store.RoleAdmin, IsAdmin: true},
		CSRF:      "token",
		ActiveTab: "customfields",
		Form:      map[string]string{"entity_type": store.CustomFieldDevice},
		CustomFieldDefs: []store.CustomFieldDef{
			{ID: "cf-1", EntityType: store.CustomFieldDevice, Name: "Owner", FieldType: "text"},
			{ID: "cf-3", EntityType: store.CustomFieldAddress, Name: "Circuit ID", FieldType: "text"},
		},
	}
	body := renderToString(t, "settings.html", data)
	for _, want := range []string{
		`action="/settings/custom-fields"`,
		`href="/settings/custom-fields/cf-1/delete"`,
		`href="/settings/custom-fields/cf-3/delete"`,
		"Owner",
		"Circuit ID",
		"Address", // entityTypeLabel for ip_address
	} {
		if !strings.Contains(body, want) {
			t.Errorf("custom fields tab missing %q", want)
		}
	}
}

// TestSettingsCertsTabRenders guards the Agent certificates settings tab.
func TestSettingsCertsTabRenders(t *testing.T) {
	data := PageData{
		User:            store.User{ID: "user-1", DisplayName: "Admin", Role: store.RoleAdmin, IsAdmin: true},
		CSRF:            "token",
		ActiveTab:       "certificates",
		CAReady:         true,
		CAFingerprint:   "AA:BB:CC",
		CAExpiry:        time.Now().Add(24 * time.Hour),
		LeafDefaultDays: 30,
	}
	body := renderToString(t, "settings.html", data)
	for _, want := range []string{
		"AA:BB:CC",
		`action="/settings/certificates/agent"`,
		`action="/settings/certificates/app"`,
		`action="/settings/certificates/rotate-ca"`,
		`href="/settings/certificates/ca.crt"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("certificates tab missing %q", want)
		}
	}
}

// TestSettingsBackupTabRenders guards the Backup & Restore settings tab.
func TestSettingsBackupTabRenders(t *testing.T) {
	data := PageData{
		User:           store.User{ID: "user-1", DisplayName: "Admin", Role: store.RoleAdmin, IsAdmin: true},
		CSRF:           "token",
		ActiveTab:      "backup",
		BackupEnabled:  true,
		BackupWritable: true,
		BackupDir:      "/var/lib/lightipam/backups",
		Backups: []backup.Backup{
			{Name: "lightipam-20260619-143005-mig16.dump", Size: 2048, Migration: 16, CreatedAt: time.Now()},
		},
	}
	body := renderToString(t, "settings.html", data)
	for _, want := range []string{
		`action="/settings/backup/create"`,
		"lightipam-20260619-143005-mig16.dump",
		`/settings/backup/lightipam-20260619-143005-mig16.dump/download`,
		"2.0 KiB",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("backup tab missing %q", want)
		}
	}
}

// TestSettingsAuthTabRenders guards the Authentication (SSO) settings tab.
func TestSettingsAuthTabRenders(t *testing.T) {
	data := PageData{
		User:      store.User{ID: "user-1", DisplayName: "Admin", Role: store.RoleAdmin, IsAdmin: true},
		CSRF:      "token",
		ActiveTab: "authentication",
		Form: map[string]string{
			"oidc_enabled":      "on",
			"oidc_issuer":       "https://idp.example.com",
			"oidc_base_url":     "https://ipam.example.com",
			"oidc_redirect_url": "https://ipam.example.com/auth/oidc/callback",
			"oidc_secret_set":   "1",
		},
	}
	recorder := httptest.NewRecorder()
	if err := Render(recorder, "settings.html", data); err != nil {
		t.Fatalf("render settings auth: %v", err)
	}
	body := recorder.Body.String()
	for _, want := range []string{
		`action="/settings/authentication"`,
		`name="oidc_issuer"`,
		`name="oidc_client_secret"`,
		"https://ipam.example.com/auth/oidc/callback",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("auth tab missing %q", want)
		}
	}
}

// TestMFASettingsRenders exercises the three MFA states: enroll (QR + key),
// freshly-enabled (recovery codes shown once), and enabled management.
func TestMFASettingsRenders(t *testing.T) {
	base := PageData{User: store.User{ID: "u1", Username: "admin"}, CSRF: "token", ActiveNav: "account"}

	t.Run("enroll", func(t *testing.T) {
		d := base
		d.TOTPSecretFormatted = "ABCD EFGH IJKL"
		d.TOTPURI = "otpauth://totp/x"
		body := renderToString(t, "mfa_settings.html", d)
		for _, want := range []string{`/account/mfa/qr.png`, "ABCD EFGH IJKL", `action="/account/mfa/enable"`} {
			if !strings.Contains(body, want) {
				t.Errorf("enroll view missing %q", want)
			}
		}
	})

	t.Run("recovery codes", func(t *testing.T) {
		d := base
		d.MFAEnabled = true
		d.RecoveryCodes = []string{"ABCDE-FGHIJ", "KLMNP-QRSTU"}
		body := renderToString(t, "mfa_settings.html", d)
		for _, want := range []string{"ABCDE-FGHIJ", "KLMNP-QRSTU", "recovery codes"} {
			if !strings.Contains(body, want) {
				t.Errorf("recovery view missing %q", want)
			}
		}
	})

	t.Run("enabled management", func(t *testing.T) {
		d := base
		d.MFAEnabled = true
		d.RecoveryRemaining = 9
		body := renderToString(t, "mfa_settings.html", d)
		if !strings.Contains(body, `action="/account/mfa/disable"`) {
			t.Error("enabled view should offer disable form")
		}
	})
}

func renderToString(t *testing.T, name string, data PageData) string {
	t.Helper()
	rec := httptest.NewRecorder()
	if err := Render(rec, name, data); err != nil {
		t.Fatalf("render %s: %v", name, err)
	}
	return rec.Body.String()
}

// TestBulkEditMarkupRenders guards the bulk-edit affordances: each table must
// post to its /bulk endpoint, render row checkboxes and an action bar, and the
// shared confirm page must carry selected ids forward as hidden inputs.
func TestBulkEditMarkupRenders(t *testing.T) {
	vlan := 20
	data := PageData{
		User:    store.User{DisplayName: "Admin"},
		CSRF:    "token",
		Subnets: []store.Subnet{{ID: "s1", Name: "Office LAN", CIDR: "192.168.10.0/24", VLAN: &vlan, Tags: []string{"core"}}},
		Subnet:  store.Subnet{ID: "s1", Name: "Office LAN", CIDR: "192.168.10.0/24"},
		Addresses: []store.IPAddress{{
			ID: "a1", Address: "192.168.10.20", State: "assigned", Tags: []string{"reserved-block"},
		}},
		AddressStates: []string{"available", "reserved", "assigned", "deprecated", "conflict"},
		DeviceGroups: []store.DeviceGroup{{
			SubnetID: "s1", SubnetName: "Office LAN", CIDR: "192.168.10.0/24",
			Devices: []store.Device{{ID: "d1", Name: "NAS", Tags: []string{"Private MAC"}}},
		}},
	}

	cases := map[string][]string{
		"subnets.html":       {`action="/subnets/bulk"`, "data-bulk-form", "data-bulk-checkbox", `value="set_vlan"`, `value="s1"`},
		"subnet_detail.html": {`action="/addresses/bulk"`, "data-bulk-checkbox", `value="set_state"`, `value="clear_device"`, `value="a1"`},
		"devices.html":       {`action="/devices/bulk"`, "data-bulk-checkbox", `value="tag_add"`, `value="d1"`},
	}
	for name, wants := range cases {
		t.Run(name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			if err := Render(recorder, name, data); err != nil {
				t.Fatalf("render %s: %v", name, err)
			}
			body := recorder.Body.String()
			for _, want := range wants {
				if !strings.Contains(body, want) {
					t.Errorf("%s missing bulk marker %q", name, want)
				}
			}
		})
	}

	t.Run("confirm.html carries bulk ids", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		confirm := PageData{
			User: store.User{DisplayName: "Admin"},
			CSRF: "token",
			Form: map[string]string{
				"heading": "Delete subnets", "message": "x", "subject": "2 subnets",
				"action": "/subnets/bulk", "cancel": "/subnets", "confirm_text": "Delete subnets",
				"ids": "s1,s2", "bulk_action": "delete",
			},
		}
		if err := Render(recorder, "confirm.html", confirm); err != nil {
			t.Fatalf("render confirm: %v", err)
		}
		body := recorder.Body.String()
		for _, want := range []string{`name="ids" value="s1"`, `name="ids" value="s2"`, `name="action" value="delete"`, `name="confirmed" value="1"`} {
			if !strings.Contains(body, want) {
				t.Errorf("confirm.html missing %q", want)
			}
		}
	})
}

// TestSettingsNotificationsTabRenders guards the Notifications (change webhooks)
// settings tab: the add form, the shared event-category partial, an inline edit
// form with the subscribed categories pre-checked, and the delivery log.
func TestSettingsNotificationsTabRenders(t *testing.T) {
	data := PageData{
		User:              store.User{ID: "user-1", DisplayName: "Admin", Role: store.RoleAdmin, IsAdmin: true},
		CSRF:              "token",
		ActiveTab:         "notifications",
		Form:              map[string]string{"enabled": "on"},
		WebhookCategories: []string{"ipam", "discovery", "scan", "security"},
		Webhooks: []store.Webhook{{
			ID:        "wh-1",
			Name:      "Ops channel",
			URL:       "https://hooks.example.com/ipam",
			HasSecret: true,
			Events:    []string{"ipam", "scan"},
			Enabled:   true,
		}},
		WebhookDeliveries: []store.WebhookDelivery{
			{ID: 1, WebhookName: "Ops channel", EventType: "subnet.created", Status: "success", StatusCode: 200},
			{ID: 2, WebhookName: "Ops channel", EventType: "scan.job.failed", Status: "failed", Error: "endpoint returned HTTP 500"},
		},
	}
	body := renderToString(t, "settings.html", data)
	for _, want := range []string{
		`action="/settings/notifications"`,
		`action="/settings/notifications/wh-1"`,
		`action="/settings/notifications/wh-1/test"`,
		`href="/settings/notifications/wh-1/delete"`,
		`name="event" value="ipam"`,
		`name="event" value="security"`,
		"Ops channel",
		"subnet.created",
		"scan.job.failed",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("notifications tab missing %q", want)
		}
	}
	// The webhook subscribes to ipam+scan: those edit checkboxes must be checked,
	// and the unsubscribed ones must not be. Find the inline edit form's checkboxes.
	if !strings.Contains(body, `value="ipam" checked`) || !strings.Contains(body, `value="scan" checked`) {
		t.Error("subscribed categories should be pre-checked in the edit form")
	}
}
