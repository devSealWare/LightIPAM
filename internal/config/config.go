package config

import (
	"crypto/rand"
	"encoding/base64"
	"log/slog"
	"os"
)

type Config struct {
	Port         string
	DatabaseURL  string
	AppSecret    []byte
	CookieSecure bool
}

func Load() Config {
	secret := os.Getenv("APP_SECRET")
	if secret == "" {
		generated := make([]byte, 32)
		if _, err := rand.Read(generated); err != nil {
			panic(err)
		}
		secret = base64.RawURLEncoding.EncodeToString(generated)
		slog.Warn("APP_SECRET is not set; generated a temporary development secret")
	}

	return Config{
		Port:         getenv("PORT", "8080"),
		DatabaseURL:  getenv("DATABASE_URL", "postgres://lightipam:lightipam@localhost:5432/lightipam?sslmode=disable"),
		AppSecret:    []byte(secret),
		CookieSecure: getenv("COOKIE_SECURE", "false") == "true",
	}
}

func getenv(key, fallback string) string {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	return value
}
