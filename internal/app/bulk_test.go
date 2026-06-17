package app

import (
	"net/url"
	"testing"
)

func TestParseBulkRequest(t *testing.T) {
	tests := []struct {
		name    string
		entity  string
		form    url.Values
		wantErr bool
		check   func(t *testing.T, req bulkRequest)
	}{
		{
			name:   "subnet set vlan",
			entity: "subnets",
			form:   url.Values{"ids": {"a", "b"}, "action": {"set_vlan"}, "vlan": {"42"}},
			check: func(t *testing.T, req bulkRequest) {
				if len(req.IDs) != 2 {
					t.Fatalf("want 2 ids, got %d", len(req.IDs))
				}
				if req.VLAN == nil || *req.VLAN != 42 {
					t.Fatalf("want vlan 42, got %v", req.VLAN)
				}
			},
		},
		{
			name:   "subnet set vlan blank clears",
			entity: "subnets",
			form:   url.Values{"ids": {"a"}, "action": {"set_vlan"}, "vlan": {"  "}},
			check: func(t *testing.T, req bulkRequest) {
				if req.VLAN != nil {
					t.Fatalf("want nil vlan (clear), got %v", *req.VLAN)
				}
			},
		},
		{
			name:    "subnet vlan out of range",
			entity:  "subnets",
			form:    url.Values{"ids": {"a"}, "action": {"set_vlan"}, "vlan": {"9999"}},
			wantErr: true,
		},
		{
			name:   "address set state",
			entity: "addresses",
			form:   url.Values{"ids": {"a"}, "action": {"set_state"}, "state": {"reserved"}, "subnet_id": {"s1"}},
			check: func(t *testing.T, req bulkRequest) {
				if req.State != "reserved" {
					t.Fatalf("want state reserved, got %q", req.State)
				}
				if req.SubnetID != "s1" {
					t.Fatalf("want subnet_id s1, got %q", req.SubnetID)
				}
			},
		},
		{
			name:    "address invalid state",
			entity:  "addresses",
			form:    url.Values{"ids": {"a"}, "action": {"set_state"}, "state": {"bogus"}},
			wantErr: true,
		},
		{
			name:   "tag add trims",
			entity: "devices",
			form:   url.Values{"ids": {"a"}, "action": {"tag_add"}, "tag": {"  core  "}},
			check: func(t *testing.T, req bulkRequest) {
				if req.Tag != "core" {
					t.Fatalf("want tag core, got %q", req.Tag)
				}
			},
		},
		{
			name:    "tag add empty",
			entity:  "devices",
			form:    url.Values{"ids": {"a"}, "action": {"tag_add"}, "tag": {"   "}},
			wantErr: true,
		},
		{
			name:    "no ids",
			entity:  "subnets",
			form:    url.Values{"action": {"delete"}},
			wantErr: true,
		},
		{
			name:    "blank ids only",
			entity:  "subnets",
			form:    url.Values{"ids": {"", "  "}, "action": {"delete"}},
			wantErr: true,
		},
		{
			name:    "no action",
			entity:  "devices",
			form:    url.Values{"ids": {"a"}},
			wantErr: true,
		},
		{
			name:    "action not allowed for entity",
			entity:  "addresses",
			form:    url.Values{"ids": {"a"}, "action": {"set_vlan"}, "vlan": {"10"}},
			wantErr: true,
		},
		{
			name:    "devices cannot set state",
			entity:  "devices",
			form:    url.Values{"ids": {"a"}, "action": {"set_state"}, "state": {"reserved"}},
			wantErr: true,
		},
		{
			name:    "unknown entity",
			entity:  "widgets",
			form:    url.Values{"ids": {"a"}, "action": {"delete"}},
			wantErr: true,
		},
		{
			name:   "delete confirmed flag",
			entity: "devices",
			form:   url.Values{"ids": {"a", " ", "b"}, "action": {"delete"}, "confirmed": {"1"}},
			check: func(t *testing.T, req bulkRequest) {
				if !req.Confirmed {
					t.Fatal("want confirmed true")
				}
				if len(req.IDs) != 2 {
					t.Fatalf("want blank id dropped, got %d ids", len(req.IDs))
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := parseBulkRequest(tt.form, tt.entity)
			if tt.wantErr {
				if err == nil {
					t.Fatal("want error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.check != nil {
				tt.check(t, req)
			}
		})
	}
}
