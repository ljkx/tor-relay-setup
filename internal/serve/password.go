package serve

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

// argon2id parameters for new hashes: RFC 9106's second recommended
// option (64 MiB, 3 passes, 4 lanes), a 16-byte salt and a 32-byte key.
const (
	argonMemory  = 64 * 1024 // KiB
	argonTime    = 3
	argonThreads = 4
	argonSaltLen = 16
	argonKeyLen  = 32

	// Limits for hashes read from serve.toml, so a hand-edited hash cannot
	// make every login take minutes or gigabytes.
	maxArgonMemory  = 1024 * 1024 // 1 GiB
	maxArgonTime    = 16
	maxArgonThreads = 64

	// MinPasswordLength and MaxPasswordLength bound new passwords.
	MinPasswordLength = 12
	MaxPasswordLength = 1024
)

// hashParams is a parsed PHC string.
type hashParams struct {
	memory  uint32
	time    uint32
	threads uint8
	salt    []byte
	key     []byte
}

var b64 = base64.RawStdEncoding

// HashPassword hashes a password with argon2id and returns the PHC string
// "$argon2id$v=19$m=65536,t=3,p=4$<salt>$<key>".
func HashPassword(password string) (string, error) {
	if err := CheckPassword(password); err != nil {
		return "", err
	}
	return hashWith(password, argonMemory, argonTime, argonThreads), nil
}

// hashWith hashes with explicit parameters (tests use cheap ones).
func hashWith(password string, memory, passes uint32, threads uint8) string {
	salt := make([]byte, argonSaltLen)
	_, _ = rand.Read(salt)
	key := argon2.IDKey([]byte(password), salt, passes, memory, threads, argonKeyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, memory, passes, threads,
		b64.EncodeToString(salt), b64.EncodeToString(key))
}

// CheckPassword enforces the length limits for a new password.
func CheckPassword(password string) error {
	switch n := len([]rune(password)); {
	case n < MinPasswordLength:
		return fmt.Errorf("the password needs at least %d characters", MinPasswordLength)
	case len(password) > MaxPasswordLength:
		return fmt.Errorf("the password is longer than %d bytes", MaxPasswordLength)
	}
	return nil
}

// parseHash reads an argon2id PHC string with sane parameters.
func parseHash(s string) (hashParams, error) {
	parts := strings.Split(s, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" {
		return hashParams{}, errors.New("not an argon2id hash in PHC format ($argon2id$v=19$m=...,t=...,p=...$salt$key)")
	}
	if parts[2] != "v="+strconv.Itoa(argon2.Version) {
		return hashParams{}, fmt.Errorf("unsupported argon2 version %q", parts[2])
	}
	var p hashParams
	for _, kv := range strings.Split(parts[3], ",") {
		k, v, _ := strings.Cut(kv, "=")
		n, err := strconv.ParseUint(v, 10, 32)
		if err != nil {
			return hashParams{}, fmt.Errorf("bad parameter %q", kv)
		}
		switch k {
		case "m":
			p.memory = uint32(n)
		case "t":
			p.time = uint32(n)
		case "p":
			if n > 255 {
				return hashParams{}, fmt.Errorf("bad parameter %q", kv)
			}
			p.threads = uint8(n)
		default:
			return hashParams{}, fmt.Errorf("unknown parameter %q", k)
		}
	}
	switch {
	case p.memory < 8*1024 || p.memory > maxArgonMemory:
		return hashParams{}, fmt.Errorf("memory m=%d KiB is outside 8192-%d", p.memory, maxArgonMemory)
	case p.time < 1 || p.time > maxArgonTime:
		return hashParams{}, fmt.Errorf("passes t=%d are outside 1-%d", p.time, maxArgonTime)
	case p.threads < 1 || p.threads > maxArgonThreads:
		return hashParams{}, fmt.Errorf("lanes p=%d are outside 1-%d", p.threads, maxArgonThreads)
	}
	var err error
	if p.salt, err = b64.DecodeString(parts[4]); err != nil || len(p.salt) < 8 {
		return hashParams{}, errors.New("bad salt")
	}
	if p.key, err = b64.DecodeString(parts[5]); err != nil || len(p.key) < 16 || len(p.key) > 64 {
		return hashParams{}, errors.New("bad key")
	}
	return p, nil
}

// VerifyPassword reports whether password matches the PHC hash, comparing
// in constant time. A malformed hash never matches.
func VerifyPassword(hash, password string) bool {
	p, err := parseHash(hash)
	if err != nil || len(password) > MaxPasswordLength {
		return false
	}
	key := argon2.IDKey([]byte(password), p.salt, p.time, p.memory, p.threads, uint32(len(p.key))) //nolint:gosec // len(p.key) is 16-64 (parseHash)
	return subtle.ConstantTimeCompare(key, p.key) == 1
}

// NewToken returns a random metrics token (256 bits, URL-safe base64) and
// the hex SHA-256 that serve.toml stores.
func NewToken() (token, sum string, err error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", "", err
	}
	token = "trs_" + base64.RawURLEncoding.EncodeToString(b)
	return token, TokenSum(token), nil
}

// TokenSum is the hex SHA-256 of a token.
func TokenSum(token string) string {
	s := sha256.Sum256([]byte(token))
	return hex.EncodeToString(s[:])
}

// tokenMatches compares a presented token with the stored SHA-256 in
// constant time.
func tokenMatches(presented string, sum []byte) bool {
	if len(sum) != sha256.Size || presented == "" {
		return false
	}
	s := sha256.Sum256([]byte(presented))
	return subtle.ConstantTimeCompare(s[:], sum) == 1
}

// randomID returns n random bytes as URL-safe base64.
func randomID(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
