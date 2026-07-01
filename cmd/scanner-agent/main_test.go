package main

import "testing"

func TestAtoiPort(t *testing.T) {
	cases := []struct {
		name     string
		in       string
		fallback int
		want     uint16
	}{
		{"in range", "8443", 161, 8443},
		{"low boundary", "1", 161, 1},
		{"high boundary", "65535", 161, 65535},
		{"empty falls back", "", 161, 161},
		{"whitespace falls back", "  ", 137, 137},
		{"non-numeric falls back", "abc", 5353, 5353},
		{"zero falls back", "0", 161, 161},
		{"negative falls back", "-1", 161, 161},
		{"above range falls back (would wrap to 1)", "65537", 161, 161},
		{"way above range falls back", "70000", 137, 137},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := atoiPort(tc.in, tc.fallback); got != tc.want {
				t.Errorf("atoiPort(%q, %d) = %d, want %d", tc.in, tc.fallback, got, tc.want)
			}
		})
	}
}

func TestHealthcheckDialAddr(t *testing.T) {
	cases := map[string]string{
		":8443":          "127.0.0.1:8443", // wildcard/empty host → loopback
		"0.0.0.0:8443":   "127.0.0.1:8443",
		"[::]:8443":      "127.0.0.1:8443",
		"127.0.0.1:8443": "127.0.0.1:8443", // explicit host preserved
		"10.0.0.5:9000":  "10.0.0.5:9000",
		"not-an-addr":    "not-an-addr", // unrecognized form dialed as-is
	}
	for in, want := range cases {
		if got := healthcheckDialAddr(in); got != want {
			t.Errorf("healthcheckDialAddr(%q) = %q, want %q", in, got, want)
		}
	}
}
