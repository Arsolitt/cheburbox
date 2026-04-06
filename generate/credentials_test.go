package generate

import (
	"crypto/ecdh"
	"encoding/base64"
	"strings"
	"testing"
)

func TestGenerateUUID(t *testing.T) {
	t.Parallel()

	id := GenerateUUID()
	if id == "" {
		t.Fatal("expected non-empty UUID")
	}
	parts := strings.Split(id, "-")
	if len(parts) != 5 {
		t.Fatalf("expected 5 parts, got %d: %q", len(parts), id)
	}
}

func TestGenerateUUIDUnique(t *testing.T) {
	t.Parallel()

	a := GenerateUUID()
	b := GenerateUUID()
	if a == b {
		t.Fatalf("two UUIDs should not be equal: %q", a)
	}
}

func TestGeneratePassword(t *testing.T) {
	t.Parallel()

	pw := GeneratePassword()
	decoded, err := base64.StdEncoding.DecodeString(pw)
	if err != nil {
		t.Fatalf("base64 decode: %v", err)
	}
	if len(decoded) != 24 {
		t.Fatalf("expected 24 bytes, got %d", len(decoded))
	}
}

func TestGeneratePasswordUnique(t *testing.T) {
	t.Parallel()

	a := GeneratePassword()
	b := GeneratePassword()
	if a == b {
		t.Fatalf("two passwords should not be equal: %q", a)
	}
}

func TestGenerateX25519KeyPair(t *testing.T) {
	t.Parallel()

	priv, pub := GenerateX25519KeyPair()
	if priv == "" {
		t.Fatal("expected non-empty private key")
	}
	if pub == "" {
		t.Fatal("expected non-empty public key")
	}
	privBytes, err := base64.StdEncoding.DecodeString(priv)
	if err != nil {
		t.Fatalf("decode private key: %v", err)
	}
	if len(privBytes) != 32 {
		t.Fatalf("expected 32-byte private key, got %d", len(privBytes))
	}
	pubBytes, err := base64.StdEncoding.DecodeString(pub)
	if err != nil {
		t.Fatalf("decode public key: %v", err)
	}
	if len(pubBytes) != 32 {
		t.Fatalf("expected 32-byte public key, got %d", len(pubBytes))
	}
}

func TestGenerateX25519KeyPairValid(t *testing.T) {
	t.Parallel()

	priv, pub := GenerateX25519KeyPair()
	privBytes, _ := base64.StdEncoding.DecodeString(priv)
	pubBytes, _ := base64.StdEncoding.DecodeString(pub)

	privateKey, err := ecdh.X25519().NewPrivateKey(privBytes)
	if err != nil {
		t.Fatalf("invalid private key: %v", err)
	}
	expectedPub := privateKey.PublicKey().Bytes()
	if string(pubBytes) != string(expectedPub) {
		t.Fatal("public key does not match private key")
	}
}

func TestGenerateShortID(t *testing.T) {
	t.Parallel()

	id := GenerateShortID()
	decoded, err := base64.StdEncoding.DecodeString(id)
	if err != nil {
		t.Fatalf("base64 decode: %v", err)
	}
	if len(decoded) < 1 || len(decoded) > 16 {
		t.Fatalf("expected 1-16 bytes, got %d", len(decoded))
	}
}
