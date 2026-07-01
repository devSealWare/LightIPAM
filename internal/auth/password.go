package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"math"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/crypto/argon2"
)

const (
	argonMemory      = 64 * 1024
	argonIterations  = 3
	argonParallelism = 4
	argonSaltLength  = 16
	argonKeyLength   = 32
)

func HashPassword(password string) (string, error) {
	salt := make([]byte, argonSaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("read salt: %w", err)
	}

	hash := argon2.IDKey([]byte(password), salt, argonIterations, argonMemory, argonParallelism, argonKeyLength)
	return fmt.Sprintf(
		"argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		argonMemory,
		argonIterations,
		argonParallelism,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash),
	), nil
}

func VerifyPassword(encoded, password string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 5 || parts[0] != "argon2id" || parts[1] != "v=19" {
		return false
	}

	params := strings.Split(parts[2], ",")
	if len(params) != 3 {
		return false
	}

	memory, err := parseParam(params[0], "m")
	if err != nil {
		return false
	}
	iterations, err := parseParam(params[1], "t")
	if err != nil {
		return false
	}
	parallelism, err := parseParam(params[2], "p")
	if err != nil {
		return false
	}

	// Bound each parameter to the width its narrowing conversion below can hold
	// (m/t → uint32, p → uint8), so a malformed or hostile encoded hash with an
	// out-of-range value fails closed here instead of silently wrapping. The checks
	// are kept local to the conversions so the bound is provable at the cast site.
	if memory <= 0 || memory > math.MaxUint32 {
		return false
	}
	if iterations <= 0 || iterations > math.MaxUint32 {
		return false
	}
	if parallelism <= 0 || parallelism > math.MaxUint8 {
		return false
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[3])
	if err != nil {
		return false
	}
	expected, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false
	}

	actual := argon2.IDKey([]byte(password), salt, uint32(iterations), uint32(memory), uint8(parallelism), uint32(len(expected)))
	return subtle.ConstantTimeCompare(actual, expected) == 1
}

// decoyHash is a real argon2id hash, computed once with the standard
// parameters, used to equalize login timing. It is derived from a random
// password so it never matches a user's input.
var decoyHash = sync.OnceValue(func() string {
	secret := make([]byte, 32)
	_, _ = rand.Read(secret)
	hash, err := HashPassword(base64.RawStdEncoding.EncodeToString(secret))
	if err != nil {
		// HashPassword only fails if the system CSPRNG is unavailable, which is
		// already fatal for session/token issuance; fall back to a constant so a
		// decoy verify still performs the Argon2 work.
		return "argon2id$v=19$m=65536,t=3,p=4$YWJjZGVmZ2hpamtsbW5vcA$ZGVjb3lkZWNveWRlY295ZGVjb3lkZWNveWRlY295ZGU"
	}
	return hash
})

// VerifyDecoy performs a password verification against a fixed decoy hash and
// discards the result. Call it on the user-not-found path so that path does the
// same Argon2 work as a wrong-password check, removing the timing oracle that
// would otherwise reveal whether a username exists.
func VerifyDecoy(password string) {
	_ = VerifyPassword(decoyHash(), password)
}

func parseParam(value, key string) (int, error) {
	prefix := key + "="
	if !strings.HasPrefix(value, prefix) {
		return 0, fmt.Errorf("missing %s", key)
	}
	return strconv.Atoi(strings.TrimPrefix(value, prefix))
}
