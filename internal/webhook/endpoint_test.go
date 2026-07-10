package webhook

import "testing"

func TestValidateURL(t *testing.T) {
	accept := []struct {
		name string
		in   string
		want string
	}{
		{"hostname", "https://example.internal/hook", "https://example.internal/hook"},
		{"private ipv4", "https://192.168.1.10:8443/hook", "https://192.168.1.10:8443/hook"},
		{"trims surrounding whitespace", "  https://example.internal/hook  ", "https://example.internal/hook"},
		// A hostname is intentionally not resolved; the literal-IP checks below are
		// the guard, not live DNS resolution.
		{"hostname is not resolved", "https://localhost/hook", "https://localhost/hook"},
	}
	for _, tc := range accept {
		t.Run("accept/"+tc.name, func(t *testing.T) {
			got, err := ValidateURL(tc.in)
			if err != nil {
				t.Fatalf("ValidateURL(%q) unexpected error: %v", tc.in, err)
			}
			if got != tc.want {
				t.Fatalf("ValidateURL(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}

	reject := []struct {
		name string
		in   string
	}{
		{"empty", ""},
		{"whitespace only", "   "},
		{"http scheme", "http://example.internal/hook"},
		{"no scheme", "not a url"},
		{"ftp scheme", "ftp://example.internal/hook"},
		{"missing host", "https://"},
		{"malformed url", "https://[::1"},
		{"loopback v4", "https://127.0.0.1/hook"},
		{"loopback v4 with port", "https://127.0.0.1:6379/hook"},
		{"loopback v6", "https://[::1]/hook"},
		{"link-local metadata", "https://169.254.169.254/latest/meta-data"},
		{"link-local v6", "https://[fe80::1]/hook"},
		{"unspecified v4", "https://0.0.0.0/hook"},
		{"unspecified v6", "https://[::]/hook"},
	}
	for _, tc := range reject {
		t.Run("reject/"+tc.name, func(t *testing.T) {
			if got, err := ValidateURL(tc.in); err == nil {
				t.Fatalf("ValidateURL(%q) = %q, want error", tc.in, got)
			}
		})
	}
}
