package generate

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"slices"
	"time"
)

const (
	certValidityDays = 365
	hoursPerDay      = 24
	certSerial       = 1
)

// GenerateSelfSignedCert creates a self-signed certificate and Ed25519 private key
// for the given server name, returning the DER-encoded certificate and the
// typed private key.
//
//nolint:revive // "generate.Generate" stutter is intentional for API clarity.
func GenerateSelfSignedCert(serverName string) ([]byte, ed25519.PrivateKey, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate ed25519 key: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(certSerial),
		Subject:      pkix.Name{CommonName: serverName},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Duration(certValidityDays*hoursPerDay) * time.Hour),
		DNSNames:     []string{serverName},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, priv.Public(), priv)
	if err != nil {
		return nil, nil, fmt.Errorf("create certificate: %w", err)
	}

	return certDER, priv, nil
}

// GenerateSelfSignedCertPEM creates a self-signed certificate and private key
// for the given server name, returning PEM-encoded certificate and PKCS#8
// private key.
//
//nolint:revive // "generate.Generate" stutter is intentional for API clarity.
func GenerateSelfSignedCertPEM(serverName string) ([]byte, []byte, error) {
	certDER, priv, err := GenerateSelfSignedCert(serverName)
	if err != nil {
		return nil, nil, fmt.Errorf("generate self-signed cert: %w", err)
	}

	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal private key: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	return certPEM, keyPEM, nil
}

// CertNeedsRegeneration checks whether a certificate needs to be regenerated
// based on whether it contains the expected server name in its DNS SANs.
//

func CertNeedsRegeneration(cert *x509.Certificate, serverName string) bool {
	if len(cert.DNSNames) == 0 {
		return true
	}
	return !slices.Contains(cert.DNSNames, serverName)
}

// ReadCertFiles reads PEM-encoded certificate and key from the given paths.
// Returns nil values without error if files do not exist.
func ReadCertFiles(certPath string, keyPath string) ([]byte, []byte, error) {
	certPEM, err := os.ReadFile(certPath)
	if os.IsNotExist(err) {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, fmt.Errorf("read cert %s: %w", certPath, err)
	}

	keyPEM, err := os.ReadFile(keyPath)
	if os.IsNotExist(err) {
		return certPEM, nil, nil
	}
	if err != nil {
		return certPEM, nil, fmt.Errorf("read key %s: %w", keyPath, err)
	}

	return certPEM, keyPEM, nil
}

// WriteCertFiles writes PEM-encoded certificate and key to the given paths.
func WriteCertFiles(certPath string, keyPath string, certPEM []byte, keyPEM []byte) error {
	//nolint:gosec // G306 — certificates are public, world-readable is intentional.
	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		return fmt.Errorf("write cert %s: %w", certPath, err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return fmt.Errorf("write key %s: %w", keyPath, err)
	}
	return nil
}

// ComputePinSHA256 computes the SHA-256 pin of a PEM-encoded certificate's public key.
func ComputePinSHA256(certPEM []byte) (string, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return "", errors.New("failed to decode PEM block")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("parse certificate: %w", err)
	}

	pubBytes, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return "", fmt.Errorf("marshal public key: %w", err)
	}

	sum := sha256.Sum256(pubBytes)
	encoded := base64.RawURLEncoding.EncodeToString(sum[:])

	return "sha256/" + encoded, nil
}
