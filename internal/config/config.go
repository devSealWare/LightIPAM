package config

import (
	"crypto/rand"
	"encoding/base64"
	"log/slog"
	"os"
	"strconv"
	"time"

	"github.com/devSealWare/LightIPAM/internal/secret"
)

type Config struct {
	Port         string
	DatabaseURL  string
	AppSecret    []byte
	CookieSecure bool

	// EncryptionKey seals secrets at rest (TOTP secrets, a future OIDC client
	// secret). It is a dedicated 32-byte key from APP_ENCRYPTION_KEY (base64) when
	// set, otherwise derived from AppSecret so single-secret deployments still
	// store secrets encrypted.
	EncryptionKey []byte

	// Session lifetime. SessionAbsoluteTimeout caps how long a session can live
	// from creation regardless of activity; SessionIdleTimeout expires a session
	// that has gone untouched for that long. Both are enforced server-side.
	SessionAbsoluteTimeout time.Duration
	SessionIdleTimeout     time.Duration

	// Login throttling. After LoginMaxAttempts failures (counted per username and
	// per client IP) within LoginWindow, further attempts are locked for
	// LoginLockout. Tuned together; keep LoginWindow >= LoginLockout so the lock
	// is fully enforced before the counted failures age out.
	LoginMaxAttempts int
	LoginWindow      time.Duration
	LoginLockout     time.Duration

	// LogoutEverywhereKeepsCurrent controls whether the "log out everywhere"
	// control keeps the acting session signed in (revoking only the user's other
	// sessions) or signs out every session including the current one. Like the
	// throttle/timeout knobs above, this is the boot-time default; an operator can
	// override it at runtime from the Settings page (persisted in app_settings).
	LogoutEverywhereKeepsCurrent bool

	// Scanner dispatch (app acts as the mTLS client to scanner agents). When
	// the client certificate files are absent, dispatch is disabled and scan
	// jobs fail cleanly instead of contacting an agent.
	ScannerClientCert string
	ScannerClientKey  string
	ScannerCACert     string
	ScanSchedulerTick time.Duration

	// ScannerAgentEndpoint, when set, is the bundled agent the app auto-enrolls
	// (as a pending agent) on boot by pulling its /register endpoint over mTLS.
	ScannerAgentEndpoint string

	// BackupDir is where pg_dump backups are written. Empty disables the backup
	// feature. In the compose stack it is a writable named volume; pg_dump is an
	// ordinary DB client, so the app needs no extra privilege.
	BackupDir string

	// OIDC SSO boot defaults. These seed the runtime-editable Authentication
	// settings; an admin can change them from the Settings page. The client
	// secret is sealed before it is persisted (never stored in plaintext).
	OIDCEnabled       bool
	OIDCIssuer        string
	OIDCClientID      string
	OIDCClientSecret  string
	OIDCBaseURL       string
	OIDCUsernameClaim string
	OIDCAutoProvision bool
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
		Port:                         getenv("PORT", "8080"),
		DatabaseURL:                  getenv("DATABASE_URL", "postgres://lightipam:lightipam@localhost:5432/lightipam?sslmode=disable"),
		AppSecret:                    []byte(secret),
		CookieSecure:                 getenv("COOKIE_SECURE", "false") == "true",
		EncryptionKey:                encryptionKey([]byte(secret)),
		SessionAbsoluteTimeout:       durationEnv("SESSION_ABSOLUTE_TIMEOUT", 12*time.Hour),
		SessionIdleTimeout:           durationEnv("SESSION_IDLE_TIMEOUT", 30*time.Minute),
		LoginMaxAttempts:             positiveInt(getenv("LOGIN_MAX_ATTEMPTS", "5"), 5),
		LoginWindow:                  durationEnv("LOGIN_ATTEMPT_WINDOW", 15*time.Minute),
		LoginLockout:                 durationEnv("LOGIN_LOCKOUT", 15*time.Minute),
		LogoutEverywhereKeepsCurrent: getenv("LOGOUT_EVERYWHERE_KEEPS_CURRENT", "false") == "true",
		ScannerClientCert:            getenv("SCANNER_CLIENT_CERT", "/certs/app.crt"),
		ScannerClientKey:             getenv("SCANNER_CLIENT_KEY", "/certs/app.key"),
		ScannerCACert:                getenv("SCANNER_CLIENT_CA", "/certs/ca.crt"),
		ScanSchedulerTick:            schedulerTick(getenv("SCAN_SCHEDULER_TICK_SECONDS", "30")),
		ScannerAgentEndpoint:         os.Getenv("SCANNER_AGENT_ENDPOINT"),
		OIDCEnabled:                  getenv("OIDC_ENABLED", "false") == "true",
		OIDCIssuer:                   os.Getenv("OIDC_ISSUER"),
		OIDCClientID:                 os.Getenv("OIDC_CLIENT_ID"),
		OIDCClientSecret:             os.Getenv("OIDC_CLIENT_SECRET"),
		OIDCBaseURL:                  os.Getenv("OIDC_BASE_URL"),
		OIDCUsernameClaim:            getenv("OIDC_USERNAME_CLAIM", "preferred_username"),
		OIDCAutoProvision:            getenv("OIDC_AUTO_PROVISION", "false") == "true",
		BackupDir:                    getenv("BACKUP_DIR", "/var/lib/lightipam/backups"),
	}
}

// encryptionKey returns the 32-byte key used to seal secrets at rest. An
// explicit APP_ENCRYPTION_KEY (base64, 32 bytes) is preferred; otherwise the key
// is derived from the app master secret so a single-secret deployment still
// stores secrets encrypted (just rotated together with APP_SECRET).
func encryptionKey(appSecret []byte) []byte {
	if raw := os.Getenv("APP_ENCRYPTION_KEY"); raw != "" {
		for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
			if decoded, err := enc.DecodeString(raw); err == nil && len(decoded) == 32 {
				return decoded
			}
		}
		slog.Warn("APP_ENCRYPTION_KEY is set but not a base64-encoded 32-byte key; deriving from APP_SECRET instead")
	}
	return secret.DeriveKey(appSecret)
}

func schedulerTick(value string) time.Duration {
	seconds, err := strconv.Atoi(value)
	if err != nil || seconds <= 0 {
		seconds = 30
	}
	return time.Duration(seconds) * time.Second
}

// durationEnv reads a Go duration string (e.g. "12h", "30m", "90s") from the
// environment, falling back to a default when unset or unparseable. A
// non-positive value also falls back, so a misconfiguration cannot disable the
// guard it controls.
func durationEnv(key string, fallback time.Duration) time.Duration {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	parsed, err := time.ParseDuration(value)
	if err != nil || parsed <= 0 {
		return fallback
	}
	return parsed
}

func positiveInt(value string, fallback int) int {
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed <= 0 {
		return fallback
	}
	return parsed
}

func getenv(key, fallback string) string {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	return value
}
