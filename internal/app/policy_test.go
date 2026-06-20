package app

import (
	"net/url"
	"testing"
	"time"

	"github.com/devSealWare/LightIPAM/internal/store"
)

func TestEvaluateOverlaps(t *testing.T) {
	tests := []struct {
		name    string
		subnets []store.PolicySubnet
		want    int
	}{
		{
			name: "disjoint subnets do not overlap",
			subnets: []store.PolicySubnet{
				{ID: "a", Name: "A", CIDR: "10.0.0.0/24"},
				{ID: "b", Name: "B", CIDR: "10.0.1.0/24"},
			},
			want: 0,
		},
		{
			name: "containment is an overlap",
			subnets: []store.PolicySubnet{
				{ID: "a", Name: "Parent", CIDR: "10.0.0.0/16"},
				{ID: "b", Name: "Child", CIDR: "10.0.5.0/24"},
			},
			want: 1,
		},
		{
			name: "identical CIDRs overlap once",
			subnets: []store.PolicySubnet{
				{ID: "a", Name: "A", CIDR: "192.168.1.0/24"},
				{ID: "b", Name: "B", CIDR: "192.168.1.0/24"},
			},
			want: 1,
		},
		{
			name: "three nested subnets produce three pairs",
			subnets: []store.PolicySubnet{
				{ID: "a", Name: "A", CIDR: "10.0.0.0/8"},
				{ID: "b", Name: "B", CIDR: "10.1.0.0/16"},
				{ID: "c", Name: "C", CIDR: "10.1.2.0/24"},
			},
			want: 3,
		},
		{
			name: "unparseable CIDR is skipped, not fatal",
			subnets: []store.PolicySubnet{
				{ID: "a", Name: "A", CIDR: "not-a-cidr"},
				{ID: "b", Name: "B", CIDR: "10.0.0.0/24"},
			},
			want: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := evaluateOverlaps(tt.subnets)
			if len(got) != tt.want {
				t.Fatalf("got %d findings, want %d: %+v", len(got), tt.want, got)
			}
			for _, f := range got {
				if f.Severity != store.SeverityCritical {
					t.Errorf("overlap finding severity = %q, want critical", f.Severity)
				}
			}
		})
	}
}

func TestEvaluateStaleRecords(t *testing.T) {
	now := time.Date(2026, 6, 20, 12, 0, 0, 0, time.UTC)
	settings := PolicySettings{StaleAfter: 30 * 24 * time.Hour}
	recent := now.Add(-1 * 24 * time.Hour)
	old := now.Add(-60 * 24 * time.Hour)

	records := []store.PolicyRecord{
		{Kind: "ip_address", Label: "10.0.0.5", State: "assigned", LastSeen: &recent},
		{Kind: "ip_address", Label: "10.0.0.6", State: "assigned", LastSeen: &old},
		{Kind: "device", Label: "printer", LastSeen: nil},
	}

	t.Run("never-seen excluded by default", func(t *testing.T) {
		got := evaluateStaleRecords(records, settings, now)
		if len(got) != 1 {
			t.Fatalf("got %d findings, want 1: %+v", len(got), got)
		}
		if got[0].Severity != store.SeverityWarning {
			t.Errorf("stale finding severity = %q, want warning", got[0].Severity)
		}
		if got[0].Link != "" || got[0].Check != checkStaleRecords {
			t.Errorf("unexpected finding shape: %+v", got[0])
		}
	})

	t.Run("never-seen included when enabled", func(t *testing.T) {
		s := settings
		s.StaleIncludeNeverSeen = true
		got := evaluateStaleRecords(records, s, now)
		if len(got) != 2 {
			t.Fatalf("got %d findings, want 2: %+v", len(got), got)
		}
		var info int
		for _, f := range got {
			if f.Severity == store.SeverityInfo {
				info++
			}
		}
		if info != 1 {
			t.Errorf("got %d info findings, want 1", info)
		}
	})

	t.Run("exactly at threshold is not yet stale", func(t *testing.T) {
		atCutoff := now.Add(-30 * 24 * time.Hour)
		got := evaluateStaleRecords([]store.PolicyRecord{
			{Kind: "ip_address", Label: "10.0.0.7", State: "reserved", LastSeen: &atCutoff},
		}, settings, now)
		if len(got) != 0 {
			t.Fatalf("got %d findings, want 0 (boundary is not before cutoff): %+v", len(got), got)
		}
	})
}

func TestEvaluateUnmanagedServices(t *testing.T) {
	discoveries := []store.PolicyDiscoveryRecord{
		{IP: "10.0.0.1", ReconcileStatus: store.ReconcileConflict, Conflict: "MAC changed", ServiceCount: 0},
		{IP: "10.0.0.2", Hostname: "nas", ReconcileStatus: store.ReconcileNew, ServiceCount: 3},
		{IP: "10.0.0.3", ReconcileStatus: store.ReconcileNew, ServiceCount: 0},
	}
	got := evaluateUnmanagedServices(discoveries)
	if len(got) != 2 {
		t.Fatalf("got %d findings, want 2: %+v", len(got), got)
	}
	if got[0].Severity != store.SeverityCritical {
		t.Errorf("conflict severity = %q, want critical", got[0].Severity)
	}
	if got[1].Severity != store.SeverityWarning {
		t.Errorf("unmanaged-with-services severity = %q, want warning", got[1].Severity)
	}
}

func TestEvaluateUnmanagedServicesConflictWithoutNote(t *testing.T) {
	got := evaluateUnmanagedServices([]store.PolicyDiscoveryRecord{
		{IP: "10.0.0.9", ReconcileStatus: store.ReconcileConflict},
	})
	if len(got) != 1 {
		t.Fatalf("got %d findings, want 1", len(got))
	}
	if got[0].Detail == "" {
		t.Error("conflict finding should carry a default detail when the stored note is empty")
	}
}

func TestSummarizeFindings(t *testing.T) {
	findings := []store.PolicyFinding{
		{Severity: store.SeverityCritical},
		{Severity: store.SeverityCritical},
		{Severity: store.SeverityWarning},
		{Severity: store.SeverityInfo},
	}
	got := summarizeFindings(findings)
	if got.Critical != 2 || got.Warning != 1 || got.Info != 1 {
		t.Fatalf("summary = %+v, want {2 1 1}", got)
	}
	if got.Total() != 4 {
		t.Errorf("Total() = %d, want 4", got.Total())
	}
}

func TestParsePolicySettingsForm(t *testing.T) {
	t.Run("valid form", func(t *testing.T) {
		form := url.Values{
			"policy_check_overlaps":   {"on"},
			"policy_check_services":   {"on"},
			"policy_stale_days":       {"45"},
			"policy_stale_never_seen": {"on"},
		}
		got, err := parsePolicySettingsForm(form)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !got.CheckOverlaps || got.CheckStale || !got.CheckServices {
			t.Errorf("toggles = %+v, want overlaps+services on, stale off", got)
		}
		if got.StaleAfter != 45*24*time.Hour {
			t.Errorf("StaleAfter = %s, want 1080h", got.StaleAfter)
		}
		if !got.StaleIncludeNeverSeen {
			t.Error("StaleIncludeNeverSeen should be true")
		}
	})

	t.Run("out-of-range days rejected", func(t *testing.T) {
		for _, days := range []string{"0", "4000", "", "abc"} {
			if _, err := parsePolicySettingsForm(url.Values{"policy_stale_days": {days}}); err == nil {
				t.Errorf("days=%q should be rejected", days)
			}
		}
	})
}

func TestPolicySettingsFormRoundTrip(t *testing.T) {
	original := PolicySettings{
		CheckOverlaps:         true,
		CheckStale:            false,
		CheckServices:         true,
		StaleAfter:            14 * 24 * time.Hour,
		StaleIncludeNeverSeen: true,
	}
	parsed, err := parsePolicySettingsForm(toValues(original.formValues()))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if parsed != original {
		t.Errorf("round trip = %+v, want %+v", parsed, original)
	}
}

// toValues converts a form-field map into url.Values for the round-trip test.
func toValues(form map[string]string) url.Values {
	v := url.Values{}
	for key, value := range form {
		v.Set(key, value)
	}
	return v
}
