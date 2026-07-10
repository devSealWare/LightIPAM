package app

import (
	"net/url"
	"reflect"
	"testing"
)

func TestParseWebhookForm(t *testing.T) {
	t.Run("valid full", func(t *testing.T) {
		form := url.Values{
			"name":    {"Ops channel"},
			"url":     {"https://hooks.example.com/ipam"},
			"event":   {"ipam", "scan", "ipam"}, // duplicate ignored
			"enabled": {"on"},
			"secret":  {"  s3cret  "},
		}
		input, rawSecret, err := parseWebhookForm(form)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if input.Name != "Ops channel" || input.URL != "https://hooks.example.com/ipam" {
			t.Fatalf("unexpected name/url: %+v", input)
		}
		if !input.Enabled {
			t.Fatalf("expected enabled")
		}
		if !reflect.DeepEqual(input.Events, []string{"ipam", "scan"}) {
			t.Fatalf("events = %v, want [ipam scan] (deduped)", input.Events)
		}
		if rawSecret != "s3cret" {
			t.Fatalf("rawSecret = %q, want trimmed secret", rawSecret)
		}
		if input.SecretSealed != nil {
			t.Fatalf("parse must not seal; SecretSealed should be nil")
		}
	})

	t.Run("no events means all, disabled", func(t *testing.T) {
		input, _, err := parseWebhookForm(url.Values{"name": {"x"}, "url": {"https://x.test/y"}})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(input.Events) != 0 {
			t.Fatalf("expected no events, got %v", input.Events)
		}
		if input.Enabled {
			t.Fatalf("expected disabled when checkbox absent")
		}
	})

	errCases := []struct {
		name string
		form url.Values
	}{
		{"missing name", url.Values{"url": {"https://x.test"}}},
		{"missing url", url.Values{"name": {"x"}}},
		{"non-http scheme", url.Values{"name": {"x"}, "url": {"ftp://x.test"}}},
		{"plain http rejected (finding 0005 SSRF guard)", url.Values{"name": {"x"}, "url": {"http://x.test"}}},
		{"loopback rejected (finding 0005 SSRF guard)", url.Values{"name": {"x"}, "url": {"https://127.0.0.1/hook"}}},
		{"link-local metadata rejected (finding 0005 SSRF guard)", url.Values{"name": {"x"}, "url": {"https://169.254.169.254/latest/meta-data"}}},
		{"url without host", url.Values{"name": {"x"}, "url": {"https://"}}},
		{"bad event category", url.Values{"name": {"x"}, "url": {"https://x.test"}, "event": {"bogus"}}},
	}
	for _, tc := range errCases {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := parseWebhookForm(tc.form); err == nil {
				t.Fatalf("expected an error for %s", tc.name)
			}
		})
	}
}
