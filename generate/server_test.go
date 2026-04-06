package generate

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/sagernet/sing-box/option"

	"github.com/Arsolitt/cheburbox/config"
)

func TestGenerateServer(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	cfg := config.Config{
		Version:  1,
		Endpoint: "1.2.3.4",
		DNS: config.DNS{
			Final:   new("dns-local"),
			Servers: []config.DNSServer{{Type: "local", Tag: "dns-local"}},
		},
		Inbounds: []config.Inbound{
			{
				Tag:        "vless-in",
				Type:       "vless",
				ListenPort: 443,
				TLS: &config.InboundTLS{
					Reality: &config.RealityConfig{
						Handshake: &config.RealityHandshake{
							Server:     "example.com",
							ServerPort: 443,
						},
					},
				},
				Users: []string{"alice"},
			},
		},
		Outbounds: []config.Outbound{
			{Type: "direct", Tag: "direct"},
		},
		Route: &config.Route{
			Final:               "direct",
			AutoDetectInterface: true,
		},
	}

	result, err := GenerateServer(dir, cfg, GenerateConfig{})
	if err != nil {
		t.Fatalf("GenerateServer: %v", err)
	}

	if result.Server != filepath.Base(dir) {
		t.Errorf("Server = %q, want %q", result.Server, filepath.Base(dir))
	}

	configFile := findFile(result.Files, "config.json")
	if configFile == nil {
		t.Fatal("config.json not found in result files")
	}

	var parsed map[string]any
	if err := json.Unmarshal(configFile.Content, &parsed); err != nil {
		t.Fatalf("parse generated config.json: %v", err)
	}
	if parsed["dns"] == nil {
		t.Error("expected dns section in generated config")
	}
	if parsed["route"] == nil {
		t.Error("expected route section in generated config")
	}
	if parsed["inbounds"] == nil {
		t.Error("expected inbounds section in generated config")
	}
	if parsed["outbounds"] == nil {
		t.Error("expected outbounds section in generated config")
	}
}

func TestGenerateServerPersistsCredentials(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	cfg := config.Config{
		Version:  1,
		Endpoint: "1.2.3.4",
		DNS: config.DNS{
			Final:   new("dns-local"),
			Servers: []config.DNSServer{{Type: "local", Tag: "dns-local"}},
		},
		Inbounds: []config.Inbound{
			{
				Tag:        "vless-in",
				Type:       "vless",
				ListenPort: 443,
				Users:      []string{"alice"},
			},
		},
		Outbounds: []config.Outbound{
			{Type: "direct", Tag: "direct"},
		},
	}

	result1, err := GenerateServer(dir, cfg, GenerateConfig{})
	if err != nil {
		t.Fatalf("first generate: %v", err)
	}

	configFile := findFile(result1.Files, "config.json")
	if err := os.WriteFile(filepath.Join(dir, "config.json"), configFile.Content, 0o644); err != nil {
		t.Fatalf("write config.json: %v", err)
	}

	result2, err := GenerateServer(dir, cfg, GenerateConfig{})
	if err != nil {
		t.Fatalf("second generate: %v", err)
	}

	configFile2 := findFile(result2.Files, "config.json")
	if string(configFile.Content) != string(configFile2.Content) {
		t.Error("regenerated config.json differs from first generation (credentials not persisted)")
	}
}

func TestGenerateServerWithBoilerplate(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	cfg := config.Config{
		Version: 1,
		DNS: config.DNS{
			Final:   new("dns-local"),
			Servers: []config.DNSServer{{Type: "local", Tag: "dns-local"}},
		},
	}

	result, err := GenerateServer(dir, cfg, GenerateConfig{})
	if err != nil {
		t.Fatalf("GenerateServer: %v", err)
	}

	configFile := findFile(result.Files, "config.json")

	var parsed map[string]any
	if err := json.Unmarshal(configFile.Content, &parsed); err != nil {
		t.Fatalf("parse: %v", err)
	}

	exp, ok := parsed["experimental"].(map[string]any)
	if !ok {
		t.Fatal("expected experimental section")
	}
	cache, ok := exp["cache_file"].(map[string]any)
	if !ok {
		t.Fatal("expected cache_file section")
	}
	if cache["enabled"] != true {
		t.Error("cache_file.enabled should be true")
	}
}

func TestGenerateServerWithHysteria2Certs(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	cfg := config.Config{
		Version: 1,
		DNS: config.DNS{
			Final:   new("dns-local"),
			Servers: []config.DNSServer{{Type: "local", Tag: "dns-local"}},
		},
		Inbounds: []config.Inbound{
			{
				Tag:        "hy2-in",
				Type:       "hysteria2",
				ListenPort: 8443,
				TLS:        &config.InboundTLS{ServerName: "hy.example.com"},
				Users:      []string{"bob"},
			},
		},
		Outbounds: []config.Outbound{
			{Type: "direct", Tag: "direct"},
		},
	}

	result, err := GenerateServer(dir, cfg, GenerateConfig{})
	if err != nil {
		t.Fatalf("GenerateServer: %v", err)
	}

	certFile := findFile(result.Files, "certs/hy.example.com.crt")
	if certFile == nil {
		t.Fatal("expected cert file for hy.example.com")
	}
	if len(certFile.Content) == 0 {
		t.Error("cert file is empty")
	}

	keyFile := findFile(result.Files, "certs/hy.example.com.key")
	if keyFile == nil {
		t.Fatal("expected key file for hy.example.com")
	}
	if len(keyFile.Content) == 0 {
		t.Error("key file is empty")
	}
}

func TestResolveCredentials(t *testing.T) {
	t.Parallel()

	cfg := config.Config{
		Inbounds: []config.Inbound{
			{
				Tag:   "vless-in",
				Type:  "vless",
				Users: []string{"alice", "bob"},
				TLS: &config.InboundTLS{
					Reality: &config.RealityConfig{
						Handshake: &config.RealityHandshake{
							Server:     "example.com",
							ServerPort: 443,
						},
					},
				},
			},
			{
				Tag:   "hy2-in",
				Type:  "hysteria2",
				Users: []string{"charlie"},
				Obfs:  &config.ObfsConfig{Type: "salamander"},
			},
		},
	}

	persisted := config.EmptyPersistedCredentials()
	persisted.InboundUsers["vless-in"] = map[string]config.UserCredentials{
		"alice": {UUID: "persisted-uuid"},
	}

	credsMap := resolveCredentials(cfg, persisted, false)

	vlessCreds := credsMap["vless-in"]
	if vlessCreds.Users["alice"].UUID != "persisted-uuid" {
		t.Errorf("alice UUID = %q, want persisted-uuid", vlessCreds.Users["alice"].UUID)
	}
	if vlessCreds.Users["bob"].UUID == "" {
		t.Error("bob UUID should have been generated")
	}
	if vlessCreds.Reality == nil {
		t.Fatal("expected Reality keys for vless-in")
	}
	if vlessCreds.Reality.PrivateKey == "" {
		t.Error("Reality private key should have been generated")
	}

	hy2Creds := credsMap["hy2-in"]
	if hy2Creds.Users["charlie"].Password == "" {
		t.Error("charlie password should have been generated")
	}
	if hy2Creds.ObfsPassword == "" {
		t.Error("obfs password should have been generated for hysteria2")
	}
}

func TestResolveCredentialsWithPersistedReality(t *testing.T) {
	t.Parallel()

	cfg := config.Config{
		Inbounds: []config.Inbound{
			{
				Tag:   "vless-in",
				Type:  "vless",
				Users: []string{"alice"},
				TLS: &config.InboundTLS{
					Reality: &config.RealityConfig{
						Handshake: &config.RealityHandshake{
							Server:     "example.com",
							ServerPort: 443,
						},
					},
				},
			},
		},
	}

	persisted := config.EmptyPersistedCredentials()
	persisted.RealityKeys["vless-in"] = config.RealityKeyPair{
		PrivateKey: "persisted-priv",
		PublicKey:  "persisted-pub",
		ShortID:    []string{"persisted-sid"},
	}
	persisted.InboundUsers["vless-in"] = map[string]config.UserCredentials{
		"alice": {UUID: "persisted-uuid"},
	}

	credsMap := resolveCredentials(cfg, persisted, false)
	vlessCreds := credsMap["vless-in"]

	if vlessCreds.Reality.PrivateKey != "persisted-priv" {
		t.Errorf("PrivateKey = %q, want persisted-priv", vlessCreds.Reality.PrivateKey)
	}
	if vlessCreds.Reality.ShortID[0] != "persisted-sid" {
		t.Errorf("ShortID[0] = %q, want persisted-sid", vlessCreds.Reality.ShortID[0])
	}
}

func TestResolveCredentialsWithPersistedObfs(t *testing.T) {
	t.Parallel()

	cfg := config.Config{
		Inbounds: []config.Inbound{
			{
				Tag:   "hy2-in",
				Type:  "hysteria2",
				Users: []string{"alice"},
				Obfs:  &config.ObfsConfig{Type: "salamander"},
			},
		},
	}

	persisted := config.EmptyPersistedCredentials()
	persisted.ObfsPasswords["hy2-in"] = "persisted-obfs-pw"
	persisted.InboundUsers["hy2-in"] = map[string]config.UserCredentials{
		"alice": {Password: "persisted-pw"},
	}

	credsMap := resolveCredentials(cfg, persisted, false)
	hy2Creds := credsMap["hy2-in"]

	if hy2Creds.ObfsPassword != "persisted-obfs-pw" {
		t.Errorf("ObfsPassword = %q, want persisted-obfs-pw", hy2Creds.ObfsPassword)
	}
}

func TestAddBoilerplate(t *testing.T) {
	t.Parallel()

	opts := &option.Options{}
	addBoilerplate(opts)

	if opts.Experimental == nil {
		t.Fatal("expected Experimental to be set")
	}
	if opts.Experimental.CacheFile == nil {
		t.Fatal("expected CacheFile to be set")
	}
	if !opts.Experimental.CacheFile.Enabled {
		t.Error("CacheFile.Enabled should be true")
	}
}

func TestParseCertPEM(t *testing.T) {
	t.Parallel()

	certPEM, _ := GenerateSelfSignedCertPEM("test.example.com")

	cert, err := parseCertPEM(certPEM)
	if err != nil {
		t.Fatalf("parseCertPEM: %v", err)
	}
	if cert == nil {
		t.Fatal("expected non-nil certificate")
	}
	if len(cert.DNSNames) != 1 || cert.DNSNames[0] != "test.example.com" {
		t.Errorf("DNSNames = %v, want [test.example.com]", cert.DNSNames)
	}
}

func TestParseCertPEMInvalid(t *testing.T) {
	t.Parallel()

	_, err := parseCertPEM([]byte("not valid PEM"))
	if err == nil {
		t.Fatal("expected error for invalid PEM")
	}
}

func TestGenerateServerClean(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	cfg1 := config.Config{
		Version:  1,
		Endpoint: "1.2.3.4",
		DNS: config.DNS{
			Final:   new("dns-local"),
			Servers: []config.DNSServer{{Type: "local", Tag: "dns-local"}},
		},
		Inbounds: []config.Inbound{
			{
				Tag:        "vless-in",
				Type:       "vless",
				ListenPort: 443,
				Users:      []string{"alice", "bob"},
			},
		},
		Outbounds: []config.Outbound{
			{Type: "direct", Tag: "direct"},
		},
	}

	result1, err := GenerateServer(dir, cfg1, GenerateConfig{})
	if err != nil {
		t.Fatalf("first generate: %v", err)
	}

	configFile := findFile(result1.Files, "config.json")
	if err := os.WriteFile(filepath.Join(dir, "config.json"), configFile.Content, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	cfg2 := config.Config{
		Version:  1,
		Endpoint: "1.2.3.4",
		DNS: config.DNS{
			Final:   new("dns-local"),
			Servers: []config.DNSServer{{Type: "local", Tag: "dns-local"}},
		},
		Inbounds: []config.Inbound{
			{
				Tag:        "vless-in",
				Type:       "vless",
				ListenPort: 443,
				Users:      []string{"alice"},
			},
		},
		Outbounds: []config.Outbound{
			{Type: "direct", Tag: "direct"},
		},
	}

	result2, err := GenerateServer(dir, cfg2, GenerateConfig{Clean: true})
	if err != nil {
		t.Fatalf("second generate: %v", err)
	}

	var parsed map[string]any
	configFile2 := findFile(result2.Files, "config.json")
	if err := json.Unmarshal(configFile2.Content, &parsed); err != nil {
		t.Fatalf("parse: %v", err)
	}

	inbounds, ok := parsed["inbounds"].([]any)
	if !ok || len(inbounds) != 1 {
		t.Fatalf("expected 1 inbound, got %d", len(inbounds))
	}

	firstIn, ok := inbounds[0].(map[string]any)
	if !ok {
		t.Fatal("inbound is not a map")
	}
	users, ok := firstIn["users"].([]any)
	if !ok || len(users) != 1 {
		t.Fatalf("expected 1 user after clean, got %d", len(users))
	}
}

func TestGenerateServerNoCleanPreservesExtraUsers(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	cfg1 := config.Config{
		Version:  1,
		Endpoint: "1.2.3.4",
		DNS: config.DNS{
			Final:   new("dns-local"),
			Servers: []config.DNSServer{{Type: "local", Tag: "dns-local"}},
		},
		Inbounds: []config.Inbound{
			{
				Tag:        "vless-in",
				Type:       "vless",
				ListenPort: 443,
				Users:      []string{"alice", "bob"},
			},
		},
		Outbounds: []config.Outbound{
			{Type: "direct", Tag: "direct"},
		},
	}

	result1, err := GenerateServer(dir, cfg1, GenerateConfig{})
	if err != nil {
		t.Fatalf("first generate: %v", err)
	}

	configFile := findFile(result1.Files, "config.json")
	if err := os.WriteFile(filepath.Join(dir, "config.json"), configFile.Content, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	cfg2 := config.Config{
		Version:  1,
		Endpoint: "1.2.3.4",
		DNS: config.DNS{
			Final:   new("dns-local"),
			Servers: []config.DNSServer{{Type: "local", Tag: "dns-local"}},
		},
		Inbounds: []config.Inbound{
			{
				Tag:        "vless-in",
				Type:       "vless",
				ListenPort: 443,
				Users:      []string{"alice"},
			},
		},
		Outbounds: []config.Outbound{
			{Type: "direct", Tag: "direct"},
		},
	}

	result2, err := GenerateServer(dir, cfg2, GenerateConfig{Clean: false})
	if err != nil {
		t.Fatalf("second generate: %v", err)
	}

	var parsed map[string]any
	configFile2 := findFile(result2.Files, "config.json")
	if err := json.Unmarshal(configFile2.Content, &parsed); err != nil {
		t.Fatalf("parse: %v", err)
	}

	inbounds, ok := parsed["inbounds"].([]any)
	if !ok || len(inbounds) != 1 {
		t.Fatalf("expected 1 inbound, got %d", len(inbounds))
	}

	firstIn, ok := inbounds[0].(map[string]any)
	if !ok {
		t.Fatal("inbound is not a map")
	}
	users, ok := firstIn["users"].([]any)
	if !ok || len(users) != 2 {
		t.Fatalf("expected 2 users without clean (extra persisted user preserved), got %d", len(users))
	}
}

func findFile(files []FileOutput, name string) *FileOutput {
	for i := range files {
		if files[i].Path == name {
			return &files[i]
		}
	}
	return nil
}
