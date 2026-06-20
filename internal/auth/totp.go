package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// TOTP parameters (RFC 6238). These are the de-facto defaults that Google
// Authenticator, 1Password, Authy, etc. assume, so enrollment works without the
// user adjusting anything.
const (
	totpPeriod = 30 // seconds per code
	totpDigits = 6
	totpSkew   = 1 // accept the adjacent windows for clock drift
)

var totpEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// GenerateTOTPSecret returns a fresh base32-encoded shared secret (160 bits).
func GenerateTOTPSecret() (string, error) {
	buf := make([]byte, 20)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate totp secret: %w", err)
	}
	return totpEncoding.EncodeToString(buf), nil
}

// totpCode computes the RFC 6238 code for a base32 secret at the given counter.
func totpCode(secret string, counter uint64) (string, error) {
	key, err := totpEncoding.DecodeString(strings.ToUpper(strings.TrimSpace(secret)))
	if err != nil {
		return "", fmt.Errorf("decode totp secret: %w", err)
	}
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], counter)
	mac := hmac.New(sha1.New, key)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	value := (uint32(sum[offset]&0x7f) << 24) |
		(uint32(sum[offset+1]) << 16) |
		(uint32(sum[offset+2]) << 8) |
		uint32(sum[offset+3])
	mod := uint32(1)
	for i := 0; i < totpDigits; i++ {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", totpDigits, value%mod), nil
}

// VerifyTOTP reports whether code is valid for secret at time t, allowing one
// window of clock skew on each side. Comparison is constant-time.
func VerifyTOTP(secret, code string, t time.Time) bool {
	code = strings.TrimSpace(code)
	if len(code) != totpDigits {
		return false
	}
	counter := uint64(t.Unix()) / totpPeriod
	for delta := -totpSkew; delta <= totpSkew; delta++ {
		want, err := totpCode(secret, counter+uint64(delta))
		if err != nil {
			return false
		}
		if subtle.ConstantTimeCompare([]byte(want), []byte(code)) == 1 {
			return true
		}
	}
	return false
}

// TOTPProvisioningURI builds the otpauth:// URI an authenticator app imports
// (rendered as a QR code or entered manually).
func TOTPProvisioningURI(secret, account, issuer string) string {
	label := url.PathEscape(issuer + ":" + account)
	q := url.Values{}
	q.Set("secret", secret)
	q.Set("issuer", issuer)
	q.Set("algorithm", "SHA1")
	q.Set("digits", fmt.Sprintf("%d", totpDigits))
	q.Set("period", fmt.Sprintf("%d", totpPeriod))
	return "otpauth://totp/" + label + "?" + q.Encode()
}

// FormatTOTPSecret groups the secret into four-character blocks for easier
// manual entry.
func FormatTOTPSecret(secret string) string {
	var b strings.Builder
	for i, r := range secret {
		if i > 0 && i%4 == 0 {
			b.WriteByte(' ')
		}
		b.WriteRune(r)
	}
	return b.String()
}

// recoveryCodeAlphabet excludes ambiguous characters (0/O, 1/I/L).
const recoveryCodeAlphabet = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"

// GenerateRecoveryCodes returns n single-use recovery codes in the form
// XXXXX-XXXXX. They are shown to the user once; only their hashes are stored.
func GenerateRecoveryCodes(n int) ([]string, error) {
	codes := make([]string, 0, n)
	for i := 0; i < n; i++ {
		raw, err := randomFromAlphabet(10)
		if err != nil {
			return nil, err
		}
		codes = append(codes, raw[:5]+"-"+raw[5:])
	}
	return codes, nil
}

func randomFromAlphabet(length int) (string, error) {
	buf := make([]byte, length)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("random recovery code: %w", err)
	}
	out := make([]byte, length)
	for i, b := range buf {
		out[i] = recoveryCodeAlphabet[int(b)%len(recoveryCodeAlphabet)]
	}
	return string(out), nil
}

// NormalizeRecoveryCode upper-cases and strips spaces/dashes so a user can type
// a code with or without its separator.
func NormalizeRecoveryCode(code string) string {
	code = strings.ToUpper(strings.TrimSpace(code))
	code = strings.ReplaceAll(code, "-", "")
	code = strings.ReplaceAll(code, " ", "")
	return code
}

// HashRecoveryCode hashes a recovery code for storage. Recovery codes are
// high-entropy, so a fast SHA-256 (over the normalized code) is sufficient and
// keeps verification cheap.
func HashRecoveryCode(code string) string {
	sum := sha256.Sum256([]byte(NormalizeRecoveryCode(code)))
	return fmt.Sprintf("%x", sum)
}
