// Package generate provides functions for generating cryptographic credentials
// used in cheburbox server configurations.
package generate

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"

	"github.com/gofrs/uuid/v5"
)

const passwordBytes = 24

// GenerateUUID returns a random UUIDv4 string.
//
//nolint:revive // "generate.Generate" stutter is intentional for API clarity.
func GenerateUUID() string {
	id, err := uuid.NewV4()
	if err != nil {
		panic("generate uuid: " + err.Error())
	}
	return id.String()
}

// GeneratePassword returns a base64-encoded 24-byte random password.
//
//nolint:revive // "generate.Generate" stutter is intentional for API clarity.
func GeneratePassword() string {
	b := make([]byte, passwordBytes)
	if _, err := rand.Read(b); err != nil {
		panic("generate password: " + err.Error())
	}
	return base64.StdEncoding.EncodeToString(b)
}

// GenerateX25519KeyPair generates an X25519 key pair and returns
// the private and public keys as base64-encoded strings.
//
//nolint:revive // "generate.Generate" stutter is intentional for API clarity.
func GenerateX25519KeyPair() (string, string) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		panic("generate x25519 key: " + err.Error())
	}
	return base64.StdEncoding.EncodeToString(key.Bytes()),
		base64.StdEncoding.EncodeToString(key.PublicKey().Bytes())
}

// GenerateShortID returns a base64-encoded 8-byte random short identifier.
//
//nolint:revive // "generate.Generate" stutter is intentional for API clarity.
func GenerateShortID() string {
	const n = 8
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("generate short id: " + err.Error())
	}
	return base64.StdEncoding.EncodeToString(b)
}

// DerivePublicKey derives the X25519 public key from a base64-encoded private key.
//
//nolint:revive // "generate.Derive" stutter is intentional for API clarity.
func DerivePublicKey(privateKeyBase64 string) (string, error) {
	privBytes, err := base64.StdEncoding.DecodeString(privateKeyBase64)
	if err != nil {
		return "", err
	}

	key, err := ecdh.X25519().NewPrivateKey(privBytes)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(key.PublicKey().Bytes()), nil
}
