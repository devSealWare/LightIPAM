package auth

import (
	"testing"
	"time"
)

func TestTOTPRoundTrip(t *testing.T) {
	secret, err := GenerateTOTPSecret()
	if err != nil {
		t.Fatalf("GenerateTOTPSecret: %v", err)
	}
	now := time.Unix(1_700_000_000, 0)
	code, err := totpCode(secret, uint64(now.Unix())/totpPeriod)
	if err != nil {
		t.Fatalf("totpCode: %v", err)
	}
	if len(code) != totpDigits {
		t.Fatalf("code length = %d, want %d", len(code), totpDigits)
	}
	if !VerifyTOTP(secret, code, now) {
		t.Fatal("freshly generated code should verify")
	}
}

// TestTOTPRFC6238Vector checks a known RFC 6238 test vector (SHA-1, 8-digit
// truncation reduced to our 6-digit output) to confirm the HMAC math.
func TestTOTPKnownVector(t *testing.T) {
	// Secret "12345678901234567890" (ASCII) base32-encoded.
	secret := totpEncoding.EncodeToString([]byte("12345678901234567890"))
	// RFC 6238 T=59s -> counter 1 -> 8-digit code 94287082 -> last 6 = 287082.
	code, err := totpCode(secret, 1)
	if err != nil {
		t.Fatalf("totpCode: %v", err)
	}
	if code != "287082" {
		t.Fatalf("RFC6238 vector: got %s, want 287082", code)
	}
}

func TestVerifyTOTPSkewAndReject(t *testing.T) {
	secret, _ := GenerateTOTPSecret()
	base := time.Unix(1_700_000_000, 0)
	prev, _ := totpCode(secret, uint64(base.Unix())/totpPeriod-1)
	if !VerifyTOTP(secret, prev, base) {
		t.Error("previous-window code should verify within skew")
	}
	if VerifyTOTP(secret, "000000", base.Add(10*time.Hour)) {
		// Extremely unlikely to be valid; guards against always-true bugs.
		t.Error("arbitrary code should not verify far from its window")
	}
	if VerifyTOTP(secret, "12345", base) {
		t.Error("wrong-length code should be rejected")
	}
}

func TestRecoveryCodes(t *testing.T) {
	codes, err := GenerateRecoveryCodes(8)
	if err != nil {
		t.Fatalf("GenerateRecoveryCodes: %v", err)
	}
	if len(codes) != 8 {
		t.Fatalf("want 8 codes, got %d", len(codes))
	}
	seen := map[string]bool{}
	for _, c := range codes {
		if len(c) != 11 || c[5] != '-' {
			t.Fatalf("unexpected code format %q", c)
		}
		h := HashRecoveryCode(c)
		if seen[h] {
			t.Fatalf("duplicate recovery code %q", c)
		}
		seen[h] = true
		// Hash must be stable across separator/case variations.
		if HashRecoveryCode(NormalizeRecoveryCode(c)) != h {
			t.Fatalf("hash not stable for %q", c)
		}
	}
}

func TestProvisioningURI(t *testing.T) {
	uri := TOTPProvisioningURI("ABCDEF", "admin", "Light IPAM")
	for _, want := range []string{"otpauth://totp/", "secret=ABCDEF", "issuer=Light+IPAM"} {
		if !contains(uri, want) {
			t.Errorf("provisioning URI %q missing %q", uri, want)
		}
	}
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && (indexOf(haystack, needle) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
