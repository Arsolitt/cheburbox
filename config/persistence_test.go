package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/sagernet/sing-box/option"
)

func TestLoadPersistedCredentialsEmpty(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	creds, err := LoadPersistedCredentials(filepath.Join(dir, "config.json"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(creds.InboundUsers) != 0 {
		t.Errorf("expected empty users, got %d", len(creds.InboundUsers))
	}
}

func TestLoadPersistedCredentialsVLESS(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	configJSON := filepath.Join(dir, "config.json")
	content := `{
		"inbounds": [{
			"type": "vless",
			"tag": "vless-in",
			"listen_port": 443,
			"tls": {
				"enabled": true,
				"reality": {
					"enabled": true,
					"private_key": "privkey123",
					"short_id": ["abcd"],
					"handshake": {"server": "example.com", "server_port": 443}
				}
			},
			"users": [
				{"name": "alice", "uuid": "uuid-alice"},
				{"name": "bob", "uuid": "uuid-bob"}
			]
		}]
	}`
	if err := os.WriteFile(configJSON, []byte(content), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	creds, err := LoadPersistedCredentials(configJSON)
	if err != nil {
		t.Fatalf("load credentials: %v", err)
	}

	if creds.InboundUsers["vless-in"]["alice"].UUID != "uuid-alice" {
		t.Errorf("alice UUID = %q, want %q", creds.InboundUsers["vless-in"]["alice"].UUID, "uuid-alice")
	}
	if creds.InboundUsers["vless-in"]["bob"].UUID != "uuid-bob" {
		t.Errorf("bob UUID = %q, want %q", creds.InboundUsers["vless-in"]["bob"].UUID, "uuid-bob")
	}
	if creds.RealityKeys["vless-in"].PrivateKey != "privkey123" {
		t.Errorf("reality private key = %q, want %q", creds.RealityKeys["vless-in"].PrivateKey, "privkey123")
	}
	if len(creds.RealityKeys["vless-in"].ShortID) != 1 || creds.RealityKeys["vless-in"].ShortID[0] != "abcd" {
		t.Errorf("reality short_id = %v, want [abcd]", creds.RealityKeys["vless-in"].ShortID)
	}
}

func TestLoadPersistedCredentialsHysteria2(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	configJSON := filepath.Join(dir, "config.json")
	content := `{
		"inbounds": [{
			"type": "hysteria2",
			"tag": "hy2-in",
			"listen_port": 443,
			"tls": {"enabled": true, "server_name": "example.com"},
			"obfs": {"type": "salamander", "password": "obfs-pw"},
			"users": [
				{"name": "charlie", "password": "pw-charlie"}
			]
		}]
	}`
	if err := os.WriteFile(configJSON, []byte(content), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	creds, err := LoadPersistedCredentials(configJSON)
	if err != nil {
		t.Fatalf("load credentials: %v", err)
	}

	if creds.InboundUsers["hy2-in"]["charlie"].Password != "pw-charlie" {
		t.Errorf("charlie password = %q, want %q", creds.InboundUsers["hy2-in"]["charlie"].Password, "pw-charlie")
	}
	if creds.ObfsPasswords["hy2-in"] != "obfs-pw" {
		t.Errorf("obfs password = %q, want %q", creds.ObfsPasswords["hy2-in"], "obfs-pw")
	}
}

func TestLoadPersistedCredentialsInvalidJSON(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	configJSON := filepath.Join(dir, "config.json")
	if err := os.WriteFile(configJSON, []byte(`{invalid json}`), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	_, err := LoadPersistedCredentials(configJSON)
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestExtractCredentialsFromOptions(t *testing.T) {
	t.Parallel()

	opts := buildTestOptions()
	creds := ExtractCredentials(opts)

	if len(creds.InboundUsers) != 2 {
		t.Fatalf("expected 2 inbound user maps, got %d", len(creds.InboundUsers))
	}
	if creds.InboundUsers["vless-in"]["alice"].UUID != "test-uuid" {
		t.Errorf("alice UUID = %q, want %q", creds.InboundUsers["vless-in"]["alice"].UUID, "test-uuid")
	}
	if creds.InboundUsers["hy2-in"]["bob"].Password != "test-password" {
		t.Errorf("bob password = %q, want %q", creds.InboundUsers["hy2-in"]["bob"].Password, "test-password")
	}
	if creds.RealityKeys["vless-in"].PrivateKey != "test-privkey" {
		t.Errorf("reality private key = %q, want %q", creds.RealityKeys["vless-in"].PrivateKey, "test-privkey")
	}
	if creds.ObfsPasswords["hy2-in"] != "test-obfs-pw" {
		t.Errorf("obfs password = %q, want %q", creds.ObfsPasswords["hy2-in"], "test-obfs-pw")
	}
}

func buildTestOptions() *option.Options {
	return &option.Options{
		Inbounds: []option.Inbound{
			{
				Type: "vless",
				Tag:  "vless-in",
				Options: &option.VLESSInboundOptions{
					Users: []option.VLESSUser{
						{Name: "alice", UUID: "test-uuid"},
					},
					InboundTLSOptionsContainer: option.InboundTLSOptionsContainer{
						TLS: &option.InboundTLSOptions{
							Enabled: true,
							Reality: &option.InboundRealityOptions{
								Enabled:    true,
								PrivateKey: "test-privkey",
								ShortID:    []string{"test-short-id"},
							},
						},
					},
				},
			},
			{
				Type: "hysteria2",
				Tag:  "hy2-in",
				Options: &option.Hysteria2InboundOptions{
					Users: []option.Hysteria2User{
						{Name: "bob", Password: "test-password"},
					},
					Obfs: &option.Hysteria2Obfs{
						Type:     "salamander",
						Password: "test-obfs-pw",
					},
					InboundTLSOptionsContainer: option.InboundTLSOptionsContainer{
						TLS: &option.InboundTLSOptions{
							Enabled:    true,
							ServerName: "example.com",
						},
					},
				},
			},
		},
	}
}
