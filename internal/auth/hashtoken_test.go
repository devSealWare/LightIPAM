package auth

import "testing"

func TestHashToken(t *testing.T) {
	// Deterministic and hex-encoded SHA-256 (64 hex chars).
	h := HashToken("lipam_secret")
	if len(h) != 64 {
		t.Fatalf("expected 64 hex chars, got %d (%q)", len(h), h)
	}
	if HashToken("lipam_secret") != h {
		t.Fatal("hash must be deterministic")
	}
	if HashToken("lipam_other") == h {
		t.Fatal("different tokens must hash differently")
	}
	if HashToken("") == h {
		t.Fatal("empty token must not collide")
	}
}
