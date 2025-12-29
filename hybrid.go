package agekd

import (
	"crypto/sha256"
	"fmt"
	"io"

	"filippo.io/age"
	"filippo.io/hpke"
	"github.com/awnumar/agekd/bech32"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/hkdf"
)

// HybridIdentityFromKey derives a hybrid age MLKEM768X25519 identity from a high-entropy key. Callers are responsible for
// ensuring that the provided key is suitably generated, e.g. 32 bytes read from crypto/rand.
func HybridIdentityFromKey(key, salt []byte) (*age.HybridIdentity, error) {
	uniformSalt := sha256.Sum256(salt)
	kdf := hkdf.New(sha256.New, key, uniformSalt[:], []byte(kdfLabelHybrid))
	secretKey := make([]byte, hybridSecretKeySize)
	if _, err := io.ReadFull(kdf, secretKey); err != nil {
		return nil, fmt.Errorf("failed to read randomness from hkdf: %w", err)
	}
	return newHybridIdentityFromSecretKey(secretKey)
}

// HybridIdentityFromPassword derives a hybrid age MLKEM768X25519 identity from a password using Argon2id, with strong default parameters.
func HybridIdentityFromPassword(password, salt []byte) (*age.HybridIdentity, error) {
	return HybridIdentityFromPasswordWithParameters(password, salt, DefaultArgon2idTime, DefaultArgon2idMemory, DefaultArgon2idThreads)
}

// HybridIdentityFromPasswordWithParameters derives a hybrid age MLKEM768X25519 identity from a password, with custom Argon2id parameters.
func HybridIdentityFromPasswordWithParameters(password, salt []byte, argon2idTime, argon2idMemory uint32, argon2idThreads uint8) (*age.HybridIdentity, error) {
	return HybridIdentityFromKey(argon2.IDKey(password, salt, argon2idTime, argon2idMemory, argon2idThreads, hybridSecretKeySize), nil)
}

// newHybridIdentityFromScalar returns a new HybridIdentity from a raw 32 byte secret key.
//
// Age does not provide a method to construct a HybridIdentity using a secret key, so the
// workaround we apply here is to create an encoded string key and ask age to parse it into
// its own *age.HybridIdentity type.
//
// Based on:
//   - https://github.com/FiloSottile/age/blob/v1.3.1/pq.go
//   - https://github.com/FiloSottile/hpke/blob/v0.4.0/pq.go
func newHybridIdentityFromSecretKey(secretKey []byte) (*age.HybridIdentity, error) {
	if len(secretKey) != hybridSecretKeySize {
		return nil, fmt.Errorf("invalid hybrid secret key")
	}
	privateKey, err := hpke.MLKEM768X25519().NewPrivateKey(secretKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create MLKEM768X25519 private key: %w", err)
	}
	privateKeyBytes, err := privateKey.Bytes()
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal MLKEM768X25519: %w", err)
	}
	identity, err := bech32.Encode("AGE-SECRET-KEY-PQ-", privateKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to bech32 encode private key")
	}
	return age.ParseHybridIdentity(identity)
}
