package generate

import (
	"crypto/x509"
	"encoding/pem"
	"path/filepath"
	"testing"
)

func TestGenerateSelfSignedCert(t *testing.T) {
	t.Parallel()

	cert, key, err := GenerateSelfSignedCert("example.com")
	if err != nil {
		t.Fatalf("GenerateSelfSignedCert: %v", err)
	}
	if cert == nil {
		t.Fatal("expected non-nil cert")
	}
	if key == nil {
		t.Fatal("expected non-nil key")
	}

	parsed, err := x509.ParseCertificate(cert)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}

	found := false
	for _, san := range parsed.DNSNames {
		if san == "example.com" {
			found = true
		}
	}
	if !found {
		t.Fatal("certificate does not contain SAN for example.com")
	}
}

func TestGenerateSelfSignedCertPEM(t *testing.T) {
	t.Parallel()

	certPEM, keyPEM, err := GenerateSelfSignedCertPEM("test.example.com")
	if err != nil {
		t.Fatalf("GenerateSelfSignedCertPEM: %v", err)
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatal("failed to decode cert PEM")
	}
	if block.Type != "CERTIFICATE" {
		t.Fatalf("expected CERTIFICATE block, got %q", block.Type)
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		t.Fatal("failed to decode key PEM")
	}
	if keyBlock.Type != "PRIVATE KEY" {
		t.Fatalf("expected PRIVATE KEY block, got %q", keyBlock.Type)
	}
}

func TestWriteOrReadCert(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert_test.pem")
	keyPath := filepath.Join(dir, "key_test.pem")

	certPEM, keyPEM, err := GenerateSelfSignedCertPEM("write.example.com")
	if err != nil {
		t.Fatalf("GenerateSelfSignedCertPEM: %v", err)
	}
	if err := WriteCertFiles(certPath, keyPath, certPEM, keyPEM); err != nil {
		t.Fatalf("write cert files: %v", err)
	}

	readCert, readKey, err := ReadCertFiles(certPath, keyPath)
	if err != nil {
		t.Fatalf("read cert files: %v", err)
	}
	if string(readCert) != string(certPEM) {
		t.Error("read cert does not match written cert")
	}
	if string(readKey) != string(keyPEM) {
		t.Error("read key does not match written key")
	}
}

func TestReadCertFilesMissing(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	certPEM, keyPEM, err := ReadCertFiles(
		filepath.Join(dir, "missing_cert.pem"),
		filepath.Join(dir, "missing_key.pem"),
	)
	if err != nil {
		t.Fatalf("expected no error for missing files: %v", err)
	}
	if certPEM != nil || keyPEM != nil {
		t.Error("expected nil for missing cert files")
	}
}

func TestCertNeedsRegeneration(t *testing.T) {
	t.Parallel()

	certPEM, _, err := GenerateSelfSignedCertPEM("original.example.com")
	if err != nil {
		t.Fatalf("GenerateSelfSignedCertPEM: %v", err)
	}
	block, _ := pem.Decode(certPEM)
	parsed, _ := x509.ParseCertificate(block.Bytes)

	if CertNeedsRegeneration(parsed, "original.example.com") {
		t.Fatal("cert with same SAN should not need regeneration")
	}
	if !CertNeedsRegeneration(parsed, "different.example.com") {
		t.Fatal("cert with different SAN should need regeneration")
	}
}

func TestWriteOrReadCertNonexistentDir(t *testing.T) {
	t.Parallel()

	certPEM, keyPEM, err := GenerateSelfSignedCertPEM("dir.example.com")
	if err != nil {
		t.Fatalf("GenerateSelfSignedCertPEM: %v", err)
	}
	err = WriteCertFiles("/nonexistent/path/cert.pem", "/nonexistent/path/key.pem", certPEM, keyPEM)
	if err == nil {
		t.Fatal("expected error for nonexistent directory")
	}
}

func TestComputePinSHA256(t *testing.T) {
	t.Parallel()

	certPEM, _, err := GenerateSelfSignedCertPEM("test.example.com")
	if err != nil {
		t.Fatalf("GenerateSelfSignedCertPEM: %v", err)
	}
	pin, err := ComputePinSHA256(certPEM)
	if err != nil {
		t.Fatalf("ComputePinSHA256: %v", err)
	}
	if pin == "" {
		t.Fatal("expected non-empty pin-sha256")
	}
	if len(pin) < 8 {
		t.Errorf("pin-sha256 too short: %q", pin)
	}
}

func TestComputePinSHA256InvalidPEM(t *testing.T) {
	t.Parallel()

	_, err := ComputePinSHA256([]byte("not valid PEM"))
	if err == nil {
		t.Fatal("expected error for invalid PEM")
	}
}
