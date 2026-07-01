package scanner

import "testing"

func TestValidateAgentEndpoint(t *testing.T) {
	accept := []struct {
		name string
		in   string
		want string
	}{
		{"compose hostname", "https://scanner-agent:8443", "https://scanner-agent:8443"},
		{"private ipv4", "https://192.168.1.10:8443", "https://192.168.1.10:8443"},
		{"private ipv4 no port", "https://10.0.0.5", "https://10.0.0.5"},
		{"trims surrounding whitespace", "  https://scanner-agent:8443  ", "https://scanner-agent:8443"},
		// A hostname is intentionally not resolved, so localhost is permitted; the
		// mTLS pinning to the managed CA is the backstop. Literal loopback IPs are
		// still rejected (see the reject table).
		{"hostname is not resolved", "https://localhost:8443", "https://localhost:8443"},
	}
	for _, tc := range accept {
		t.Run("accept/"+tc.name, func(t *testing.T) {
			got, err := ValidateAgentEndpoint(tc.in)
			if err != nil {
				t.Fatalf("ValidateAgentEndpoint(%q) unexpected error: %v", tc.in, err)
			}
			if got != tc.want {
				t.Fatalf("ValidateAgentEndpoint(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}

	reject := []struct {
		name string
		in   string
	}{
		{"empty", ""},
		{"whitespace only", "   "},
		{"http scheme", "http://scanner-agent:8443"},
		{"no scheme", "not a url"},
		{"ftp scheme", "ftp://scanner-agent:8443"},
		{"missing host", "https://"},
		{"malformed url", "https://[::1"},
		{"loopback v4", "https://127.0.0.1"},
		{"loopback v4 with port", "https://127.0.0.1:6379"},
		{"loopback v6", "https://[::1]:8443"},
		{"link-local metadata", "https://169.254.169.254"},
		{"link-local v6", "https://[fe80::1]:8443"},
		{"unspecified v4", "https://0.0.0.0:8443"},
		{"unspecified v6", "https://[::]:8443"},
	}
	for _, tc := range reject {
		t.Run("reject/"+tc.name, func(t *testing.T) {
			if got, err := ValidateAgentEndpoint(tc.in); err == nil {
				t.Fatalf("ValidateAgentEndpoint(%q) = %q, want error", tc.in, got)
			}
		})
	}
}
