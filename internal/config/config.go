package config

import (
	"crypto/rand"
	"encoding/base64"
	"log/slog"
	"os"
	"strconv"
	"time"
)

type Config struct {
	Port         string
	DatabaseURL  string
	AppSecret    []byte
	CookieSecure bool

	// Scanner dispatch (app acts as the mTLS client to scanner agents). When
	// the client certificate files are absent, dispatch is disabled and scan
	// jobs fail cleanly instead of contacting an agent.
	ScannerClientCert string
	ScannerClientKey  string
	ScannerCACert     string
	ScanSchedulerTick time.Duration
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
		Port:              getenv("PORT", "8080"),
		DatabaseURL:       getenv("DATABASE_URL", "postgres://lightipam:lightipam@localhost:5432/lightipam?sslmode=disable"),
		AppSecret:         []byte(secret),
		CookieSecure:      getenv("COOKIE_SECURE", "false") == "true",
		ScannerClientCert: getenv("SCANNER_CLIENT_CERT", "/certs/app.crt"),
		ScannerClientKey:  getenv("SCANNER_CLIENT_KEY", "/certs/app.key"),
		ScannerCACert:     getenv("SCANNER_CLIENT_CA", "/certs/ca.crt"),
		ScanSchedulerTick: schedulerTick(getenv("SCAN_SCHEDULER_TICK_SECONDS", "30")),
	}
}

func schedulerTick(value string) time.Duration {
	seconds, err := strconv.Atoi(value)
	if err != nil || seconds <= 0 {
		seconds = 30
	}
	return time.Duration(seconds) * time.Second
}

func getenv(key, fallback string) string {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	return value
}
