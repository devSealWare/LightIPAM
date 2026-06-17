package ui

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"

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

// TestBulkEditMarkupRenders guards the bulk-edit affordances: each table must
// post to its /bulk endpoint, render row checkboxes and an action bar, and the
// shared confirm page must carry selected ids forward as hidden inputs.
func TestBulkEditMarkupRenders(t *testing.T) {
	vlan := 20
	data := PageData{
		User: store.User{DisplayName: "Admin"},
		CSRF: "token",
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
