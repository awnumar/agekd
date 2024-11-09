package agekd

import (
	"crypto/sha256"
	"fmt"
	"io"
	"strings"

	"github.com/awnumar/agekd/bech32"

	"filippo.io/age"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

const (
	DefaultArgon2idTime    uint32 = 8
	DefaultArgon2idMemory  uint32 = 500000 // KiB = 512 MB
	DefaultArgon2idThreads uint8  = 8
)

// X25519IdentityFromKey derives an age identity from a high-entropy key. Callers are responsible for
// ensuring that the provided key is suitably generated, e.g. by reading it from `crypto/rand`.
func X25519IdentityFromKey(key, salt []byte) (*age.X25519Identity, error) {
	kdf := hkdf.New(sha256.New, key, salt, []byte("github.com/awnumar/agekd"))
	secretKey := make([]byte, curve25519.ScalarSize)
	if _, err := io.ReadFull(kdf, secretKey); err != nil {
		return nil, fmt.Errorf("failed to read randomness from hkdf: %w", err)
	}
	return newX25519IdentityFromScalar(secretKey)
}

// X25519IdentityFromPassword derives an age identity from a password using Argon2id, with strong default parameters.
func X25519IdentityFromPassword(password, salt []byte) (*age.X25519Identity, error) {
	return newX25519IdentityFromScalar(argon2.IDKey(password, salt, DefaultArgon2idTime, DefaultArgon2idMemory, DefaultArgon2idThreads, 32))
}

// X25519IdentityFromPasswordWithParameters derives an age identity from a password, with custom Argon2id parameters.
func X25519IdentityFromPasswordWithParameters(password, salt []byte, argon2idTime, argon2idMemory uint32, argon2idThreads uint8) (*age.X25519Identity, error) {
	return newX25519IdentityFromScalar(argon2.IDKey(password, salt, argon2idTime, argon2idMemory, argon2idThreads, 32))
}

// newX25519IdentityFromScalar returns a new X25519Identity from a raw Curve25519 scalar.
//
// Age does not provide a method to construct an X25519Identity using a secret key, so the
// workaround we apply here is to create an encoded string key and ask age to parse it into
// its own *age.X25519Identity type.
//
// Based on: https://github.com/FiloSottile/age/blob/v1.2.0/x25519.go
func newX25519IdentityFromScalar(secretKey []byte) (*age.X25519Identity, error) {
	if len(secretKey) != curve25519.ScalarSize {
		return nil, fmt.Errorf("invalid X25519 secret key")
	}
	s, err := bech32.Encode("AGE-SECRET-KEY-", secretKey)
	if err != nil {
		return nil, fmt.Errorf("failed to bech32 encode secret key: %w", err)
	}
	return age.ParseX25519Identity(strings.ToUpper(s))
}
