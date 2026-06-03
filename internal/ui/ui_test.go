package ui

import (
	"net/http/httptest"
	"testing"

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
		ScanTypes:     []string{"host_discovery", "service_detection", "os_probe", "combined"},
		ScanModes:     []string{"passive", "light_active", "standard_active", "deep_active"},
		AgentStatuses: []string{"pending", "active", "disabled", "revoked"},
		DispatchReady: true,
		Discoveries: []store.Discovery{{
			ID:              "disc-1",
			IP:              "192.168.10.42",
			MAC:             "aa:bb:cc:dd:ee:ff",
			Hostname:        "printer.local",
			OSFamily:        "Linux",
			OSDetail:        "Linux 5.x",
			Services:        []store.DiscoveryService{{Protocol: "tcp", Port: 9100, State: "open", ServiceName: "jetdirect"}},
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
