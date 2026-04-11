package generate

import (
	"crypto/ecdh"
	"encoding/base64"
	"strings"
	"testing"
)

func TestGenerateUUID(t *testing.T) {
	t.Parallel()

	id, err := GenerateUUID()
	if err != nil {
		t.Fatalf("GenerateUUID: %v", err)
	}
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

	a, err := GenerateUUID()
	if err != nil {
		t.Fatalf("GenerateUUID: %v", err)
	}
	b, err := GenerateUUID()
	if err != nil {
		t.Fatalf("GenerateUUID: %v", err)
	}
	if a == b {
		t.Fatalf("two UUIDs should not be equal: %q", a)
	}
}

func TestGeneratePassword(t *testing.T) {
	t.Parallel()

	pw, err := GeneratePassword()
	if err != nil {
		t.Fatalf("GeneratePassword: %v", err)
	}
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

	a, err := GeneratePassword()
	if err != nil {
		t.Fatalf("GeneratePassword: %v", err)
	}
	b, err := GeneratePassword()
	if err != nil {
		t.Fatalf("GeneratePassword: %v", err)
	}
	if a == b {
		t.Fatalf("two passwords should not be equal: %q", a)
	}
}

func TestGenerateX25519KeyPair(t *testing.T) {
	t.Parallel()

	priv, pub, err := GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("GenerateX25519KeyPair: %v", err)
	}
	if priv == "" {
		t.Fatal("expected non-empty private key")
	}
	if pub == "" {
		t.Fatal("expected non-empty public key")
	}
	privBytes, err := base64.RawURLEncoding.DecodeString(priv)
	if err != nil {
		t.Fatalf("decode private key: %v", err)
	}
	if len(privBytes) != 32 {
		t.Fatalf("expected 32-byte private key, got %d", len(privBytes))
	}
	pubBytes, err := base64.RawURLEncoding.DecodeString(pub)
	if err != nil {
		t.Fatalf("decode public key: %v", err)
	}
	if len(pubBytes) != 32 {
		t.Fatalf("expected 32-byte public key, got %d", len(pubBytes))
	}
}

func TestGenerateX25519KeyPairValid(t *testing.T) {
	t.Parallel()

	priv, pub, err := GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("GenerateX25519KeyPair: %v", err)
	}
	privBytes, _ := base64.RawURLEncoding.DecodeString(priv)
	pubBytes, _ := base64.RawURLEncoding.DecodeString(pub)

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

	id, err := GenerateShortID()
	if err != nil {
		t.Fatalf("GenerateShortID: %v", err)
	}
	decoded, err := base64.RawURLEncoding.DecodeString(id)
	if err != nil {
		t.Fatalf("base64 decode: %v", err)
	}
	if len(decoded) < 1 || len(decoded) > 16 {
		t.Fatalf("expected 1-16 bytes, got %d", len(decoded))
	}
}

func TestDerivePublicKey(t *testing.T) {
	t.Parallel()

	priv, expectedPub, err := GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("GenerateX25519KeyPair: %v", err)
	}

	gotPub, err := DerivePublicKey(priv)
	if err != nil {
		t.Fatalf("DerivePublicKey: %v", err)
	}
	if gotPub != expectedPub {
		t.Errorf("DerivePublicKey = %q, want %q", gotPub, expectedPub)
	}
}

func TestDerivePublicKeyInvalidBase64(t *testing.T) {
	t.Parallel()

	_, err := DerivePublicKey("not-base64!!!")
	if err == nil {
		t.Fatal("expected error for invalid base64")
	}
}

func TestDerivePublicKeyInvalidKey(t *testing.T) {
	t.Parallel()

	shortKey := base64.StdEncoding.EncodeToString([]byte("too-short"))
	_, err := DerivePublicKey(shortKey)
	if err == nil {
		t.Fatal("expected error for invalid key length")
	}
}
