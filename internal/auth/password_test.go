package auth

import (
	"strings"
	"testing"
)

func TestVerifyPasswordRoundTrip(t *testing.T) {
	const password = "correct horse battery staple"
	good, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	// The happy path must be unchanged by the bounds hardening: a standard
	// m=65536,t=3,p=4 hash verifies, and a wrong password does not.
	if !strings.Contains(good, "m=65536,t=3,p=4") {
		t.Fatalf("unexpected default parameters in %q", good)
	}
	if !VerifyPassword(good, password) {
		t.Fatal("a freshly hashed password must verify")
	}
	if VerifyPassword(good, "wrong password") {
		t.Fatal("a wrong password must not verify")
	}
}

func TestVerifyPasswordRejectsOutOfRangeParams(t *testing.T) {
	good, err := HashPassword("pw")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	// Each case mutates only the parameter segment of a valid hash (the base64
	// salt/digest use no '=' so the replaces cannot touch them), so it is the new
	// bound — not a decode failure — that fails the verification closed.
	cases := []struct {
		name    string
		encoded string
	}{
		{"oversized m", strings.Replace(good, "m=65536", "m=4294967296", 1)},
		{"oversized t", strings.Replace(good, "t=3", "t=4294967296", 1)},
		{"oversized p", strings.Replace(good, "p=4", "p=256", 1)},
		{"zero m", strings.Replace(good, "m=65536", "m=0", 1)},
		{"negative t", strings.Replace(good, "t=3", "t=-1", 1)},
		{"non-numeric p", strings.Replace(good, "p=4", "p=x", 1)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.encoded == good {
				t.Fatalf("test setup: %s did not mutate the hash", tc.name)
			}
			if VerifyPassword(tc.encoded, "pw") {
				t.Fatalf("VerifyPassword must reject %s: %q", tc.name, tc.encoded)
			}
		})
	}
}
