// Package secret seals small application secrets (e.g. an OIDC client secret)
// so they are never stored or rendered in plaintext. It uses AES-256-GCM with a
// key derived from the app's master key material; the on-disk form is a
// versioned, URL-safe-base64 token so the scheme can be rotated later.
package secret

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

// sealedPrefix tags the current sealing scheme (AES-256-GCM). A future scheme
// can add a new prefix while Open keeps understanding old tokens.
const sealedPrefix = "v1."

// ErrKeyLength is returned when a sealing key is not 32 bytes (AES-256).
var ErrKeyLength = errors.New("secret: key must be 32 bytes")

// Sealer encrypts and decrypts secrets with a fixed 256-bit key.
type Sealer struct {
	aead cipher.AEAD
}

// NewSealer builds a Sealer from a 32-byte key.
func NewSealer(key []byte) (*Sealer, error) {
	if len(key) != 32 {
		return nil, ErrKeyLength
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("secret: new cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("secret: new gcm: %w", err)
	}
	return &Sealer{aead: aead}, nil
}

// DeriveKey turns arbitrary master key material (e.g. APP_SECRET) into a
// fixed-length 256-bit sealing key. A dedicated, high-entropy key is preferred,
// but deriving from the existing app secret keeps single-secret deployments
// working without storing anything in plaintext.
func DeriveKey(material []byte) []byte {
	sum := sha256.Sum256(append([]byte("lightipam:secret:v1:"), material...))
	return sum[:]
}

// Seal encrypts plaintext and returns a versioned, URL-safe token. An empty
// plaintext seals to an empty string so callers can treat "" as "unset".
func (s *Sealer) Seal(plaintext string) (string, error) {
	if plaintext == "" {
		return "", nil
	}
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("secret: read nonce: %w", err)
	}
	ciphertext := s.aead.Seal(nonce, nonce, []byte(plaintext), nil)
	return sealedPrefix + base64.RawURLEncoding.EncodeToString(ciphertext), nil
}

// Open decrypts a token produced by Seal. An empty token opens to an empty
// string. A token with an unknown prefix, bad base64, or a failed
// authentication check returns an error.
func (s *Sealer) Open(token string) (string, error) {
	if token == "" {
		return "", nil
	}
	if !strings.HasPrefix(token, sealedPrefix) {
		return "", errors.New("secret: unknown sealed format")
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(token, sealedPrefix))
	if err != nil {
		return "", fmt.Errorf("secret: decode: %w", err)
	}
	nonceSize := s.aead.NonceSize()
	if len(raw) < nonceSize {
		return "", errors.New("secret: ciphertext too short")
	}
	nonce, ciphertext := raw[:nonceSize], raw[nonceSize:]
	plaintext, err := s.aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("secret: open: %w", err)
	}
	return string(plaintext), nil
}

// IsSealed reports whether a value is in the sealed token form. It lets callers
// avoid double-sealing a value and recognize already-encrypted storage.
func IsSealed(value string) bool {
	return strings.HasPrefix(value, sealedPrefix)
}
