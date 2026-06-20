package app

import (
	"net/url"
	"testing"
)

func TestParseOIDCSettingsForm(t *testing.T) {
	t.Run("disabled needs nothing", func(t *testing.T) {
		s, err := parseOIDCSettingsForm(url.Values{})
		if err != nil {
			t.Fatalf("disabled form should be valid: %v", err)
		}
		if s.Enabled {
			t.Error("should be disabled")
		}
		if s.UsernameClaim != "preferred_username" {
			t.Errorf("default claim = %q", s.UsernameClaim)
		}
	})

	t.Run("enabled requires fields", func(t *testing.T) {
		_, err := parseOIDCSettingsForm(url.Values{"oidc_enabled": {"on"}})
		if err == nil {
			t.Fatal("enabling without issuer/client/base should error")
		}
	})

	t.Run("issuer must be https", func(t *testing.T) {
		_, err := parseOIDCSettingsForm(url.Values{
			"oidc_enabled":   {"on"},
			"oidc_issuer":    {"http://idp.example.com"},
			"oidc_client_id": {"app"},
			"oidc_base_url":  {"https://ipam.example.com"},
		})
		if err == nil {
			t.Fatal("http issuer should be rejected")
		}
	})

	t.Run("valid enabled", func(t *testing.T) {
		s, err := parseOIDCSettingsForm(url.Values{
			"oidc_enabled":        {"on"},
			"oidc_issuer":         {"https://idp.example.com/"},
			"oidc_client_id":      {"app"},
			"oidc_client_secret":  {"sekret"},
			"oidc_base_url":       {"https://ipam.example.com/"},
			"oidc_auto_provision": {"on"},
		})
		if err != nil {
			t.Fatalf("valid form: %v", err)
		}
		if s.Issuer != "https://idp.example.com" {
			t.Errorf("issuer trailing slash not trimmed: %q", s.Issuer)
		}
		if s.redirectURL() != "https://ipam.example.com/auth/oidc/callback" {
			t.Errorf("redirect URL = %q", s.redirectURL())
		}
		if !s.configured() {
			t.Error("should be configured")
		}
		if s.ClientSecret != "sekret" || !s.AutoProvision {
			t.Error("secret/auto-provision not carried")
		}
	})
}

func TestOIDCUsername(t *testing.T) {
	cases := []struct {
		name   string
		claims map[string]any
		claim  string
		want   string
	}{
		{"preferred", map[string]any{"preferred_username": "alice"}, "preferred_username", "alice"},
		{"custom claim", map[string]any{"login": "bob", "preferred_username": "ignored"}, "login", "bob"},
		{"email localpart", map[string]any{"email": "carol@example.com"}, "preferred_username", "carol"},
		{"fallback sub", map[string]any{"sub": "xyz"}, "preferred_username", "xyz"},
		{"empty", map[string]any{}, "preferred_username", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := oidcUsername(tc.claims, tc.claim); got != tc.want {
				t.Errorf("oidcUsername = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestOIDCDisplayName(t *testing.T) {
	if got := oidcDisplayName(map[string]any{"name": "Alice A"}, "alice"); got != "Alice A" {
		t.Errorf("got %q", got)
	}
	if got := oidcDisplayName(map[string]any{}, "alice"); got != "alice" {
		t.Errorf("fallback got %q", got)
	}
}
