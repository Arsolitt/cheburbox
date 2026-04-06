package generate

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
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
func GenerateSelfSignedCert(serverName string) ([]byte, ed25519.PrivateKey) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic("generate ed25519 key: " + err.Error())
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
		panic("create certificate: " + err.Error())
	}

	return certDER, priv
}

// GenerateSelfSignedCertPEM creates a self-signed certificate and private key
// for the given server name, returning PEM-encoded certificate and PKCS#8
// private key.
//
//nolint:revive // "generate.Generate" stutter is intentional for API clarity.
func GenerateSelfSignedCertPEM(serverName string) ([]byte, []byte) {
	certDER, priv := GenerateSelfSignedCert(serverName)

	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		panic("marshal private key: " + err.Error())
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	return certPEM, keyPEM
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
