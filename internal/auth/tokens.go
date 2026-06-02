package auth

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

func RandomToken(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("read random token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(bytes), nil
}
