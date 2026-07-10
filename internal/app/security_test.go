package app

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSecurityHeaders(t *testing.T) {
	noop := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})

	t.Run("CSP includes base-uri and object-src", func(t *testing.T) {
		rr := httptest.NewRecorder()
		securityHeaders(noop, false).ServeHTTP(rr, httptest.NewRequest("GET", "/", nil))
		csp := rr.Header().Get("Content-Security-Policy")
		for _, want := range []string{"base-uri 'self'", "object-src 'none'"} {
			if !strings.Contains(csp, want) {
				t.Errorf("CSP %q missing %q", csp, want)
			}
		}
	})

	t.Run("HSTS omitted when disabled", func(t *testing.T) {
		rr := httptest.NewRecorder()
		securityHeaders(noop, false).ServeHTTP(rr, httptest.NewRequest("GET", "/", nil))
		if got := rr.Header().Get("Strict-Transport-Security"); got != "" {
			t.Errorf("expected no HSTS header, got %q", got)
		}
	})

	t.Run("HSTS set when enabled", func(t *testing.T) {
		rr := httptest.NewRecorder()
		securityHeaders(noop, true).ServeHTTP(rr, httptest.NewRequest("GET", "/", nil))
		if got := rr.Header().Get("Strict-Transport-Security"); got != "max-age=31536000; includeSubDomains" {
			t.Errorf("unexpected HSTS header: %q", got)
		}
	})
}
