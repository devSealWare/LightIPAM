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
