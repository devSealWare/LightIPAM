package main

import "testing"

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
