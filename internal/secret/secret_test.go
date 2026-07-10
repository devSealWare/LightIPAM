package secret

import (
	"encoding/base64"
	"strings"
	"testing"
)

func newTestSealer(t *testing.T) *Sealer {
	t.Helper()
	s, err := NewSealer(DeriveKey([]byte("test-master-secret")))
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}
	return s
}

func TestNewSealerKeyLength(t *testing.T) {
	if _, err := NewSealer([]byte("short")); err != ErrKeyLength {
		t.Fatalf("want ErrKeyLength, got %v", err)
	}
	if _, err := NewSealer(DeriveKey([]byte("anything"))); err != nil {
		t.Fatalf("derived key should be valid: %v", err)
	}
}

func TestSealOpenRoundTrip(t *testing.T) {
	s := newTestSealer(t)
	for _, plaintext := range []string{"hunter2", "a-much-longer-oidc-client-secret-value", "unicode✓"} {
		token, err := s.Seal(plaintext)
		if err != nil {
			t.Fatalf("Seal(%q): %v", plaintext, err)
		}
		if token == plaintext {
			t.Fatalf("token must not equal plaintext for %q", plaintext)
		}
		if !strings.HasPrefix(token, sealedPrefix) {
			t.Fatalf("token %q should be in the sealed form", token)
		}
		got, err := s.Open(token)
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		if got != plaintext {
			t.Fatalf("round trip: want %q, got %q", plaintext, got)
		}
	}
}

func TestSealEmpty(t *testing.T) {
	s := newTestSealer(t)
	token, err := s.Seal("")
	if err != nil || token != "" {
		t.Fatalf("empty plaintext should seal to empty string, got %q, %v", token, err)
	}
	got, err := s.Open("")
	if err != nil || got != "" {
		t.Fatalf("empty token should open to empty string, got %q, %v", got, err)
	}
}

func TestSealRandomized(t *testing.T) {
	s := newTestSealer(t)
	a, _ := s.Seal("same")
	b, _ := s.Seal("same")
	if a == b {
		t.Fatal("two seals of the same plaintext should differ (random nonce)")
	}
}

func TestOpenRejectsTampering(t *testing.T) {
	s := newTestSealer(t)
	token, _ := s.Seal("secret")
	// Flip a decoded ciphertext byte, not the trailing base64 character: RawURLEncoding
	// pads the last group's unused low bits with zeros, so a fixed-sentinel edit of the
	// last character can land entirely within those padding bits and decode to the same
	// byte — a no-op tamper that made this test flaky (~1/16 to ~1/4 of runs, depending
	// on ciphertext length mod 3). XORing a real decoded byte always changes the data.
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(token, sealedPrefix))
	if err != nil {
		t.Fatalf("decode token: %v", err)
	}
	raw[len(raw)-1] ^= 0xFF
	tampered := sealedPrefix + base64.RawURLEncoding.EncodeToString(raw)
	if _, err := s.Open(tampered); err == nil {
		t.Fatal("tampered token should fail to open")
	}
	if _, err := s.Open("plain-not-sealed"); err == nil {
		t.Fatal("unknown format should fail to open")
	}
}

func TestOpenWrongKey(t *testing.T) {
	s := newTestSealer(t)
	token, _ := s.Seal("secret")
	other, _ := NewSealer(DeriveKey([]byte("different-master")))
	if _, err := other.Open(token); err == nil {
		t.Fatal("opening with the wrong key should fail")
	}
}
