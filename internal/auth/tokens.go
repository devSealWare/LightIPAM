package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

func RandomToken(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("read random token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(bytes), nil
}

// HashToken returns the hex SHA-256 of an API token. API tokens are high-entropy
// random strings, so a fast cryptographic hash (not a slow password KDF) is the
// right at-rest representation: non-reversible and supporting an indexed equality
// lookup. Only the hash is stored; the plaintext is shown once at creation.
func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
