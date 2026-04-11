// Package generate provides functions for generating cryptographic credentials
// used in cheburbox server configurations.
package generate

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"github.com/gofrs/uuid/v5"
)

const passwordBytes = 24

// GenerateUUID returns a random UUIDv4 string.
//
//nolint:revive // "generate.Generate" stutter is intentional for API clarity.
func GenerateUUID() (string, error) {
	id, err := uuid.NewV4()
	if err != nil {
		return "", fmt.Errorf("generate uuid: %w", err)
	}
	return id.String(), nil
}

// GeneratePassword returns a base64-encoded 24-byte random password.
//
//nolint:revive // "generate.Generate" stutter is intentional for API clarity.
func GeneratePassword() (string, error) {
	b := make([]byte, passwordBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate password: %w", err)
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

// GenerateX25519KeyPair generates an X25519 key pair and returns
// the private and public keys as base64-encoded strings.
//
//nolint:revive // "generate.Generate" stutter is intentional for API clarity.
func GenerateX25519KeyPair() (string, string, error) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return "", "", fmt.Errorf("generate x25519 key: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(key.Bytes()),
		base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes()), nil
}

// GenerateShortID returns a base64-encoded 8-byte random short identifier.
//
//nolint:revive // "generate.Generate" stutter is intentional for API clarity.
func GenerateShortID() (string, error) {
	const n = 8
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate short id: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// DerivePublicKey derives the X25519 public key from a base64-encoded private key.
//

func DerivePublicKey(privateKeyBase64 string) (string, error) {
	privBytes, err := decodeBase64Key(privateKeyBase64)
	if err != nil {
		return "", err
	}

	key, err := ecdh.X25519().NewPrivateKey(privBytes)
	if err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes()), nil
}

func decodeBase64Key(s string) ([]byte, error) {
	for _, enc := range []struct {
		dec  *base64.Encoding
		name string
	}{
		{base64.StdEncoding, "std"},
		{base64.RawStdEncoding, "raw-std"},
		{base64.RawURLEncoding, "raw-url"},
	} {
		if b, err := enc.dec.DecodeString(s); err == nil {
			return b, nil
		}
	}

	return nil, fmt.Errorf("decode base64 key: all encodings failed for %q", s)
}
