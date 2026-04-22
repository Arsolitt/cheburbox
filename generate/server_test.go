package generate

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
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
				Users: []config.InboundUser{{Name: "alice"}},
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
				Users:      []config.InboundUser{{Name: "alice"}},
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

	if _, ok := parsed["experimental"]; ok {
		t.Error("experimental section should not be present when cache_file is not explicitly enabled")
	}
}

func TestGenerateServerWithCacheFileEnabled(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	enabled := true
	cfg := config.Config{
		Version: 1,
		DNS: config.DNS{
			Final:   new("dns-local"),
			Servers: []config.DNSServer{{Type: "local", Tag: "dns-local"}},
		},
		Experimental: &config.Experimental{
			CacheFile: &config.CacheFileConfig{Enabled: &enabled},
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
				Users:      []config.InboundUser{{Name: "bob"}},
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

func TestGenerateUserCredsDefaultFlow(t *testing.T) {
	t.Parallel()

	creds, err := generateUserCreds("vless")
	if err != nil {
		t.Fatalf("generateUserCreds: %v", err)
	}
	if creds.UUID == "" {
		t.Error("expected non-empty UUID for vless")
	}
	if creds.Flow != "xtls-rprx-vision" {
		t.Errorf("Flow = %q, want xtls-rprx-vision", creds.Flow)
	}
}

func TestResolveCredentials(t *testing.T) {
	t.Parallel()

	cfg := config.Config{
		Inbounds: []config.Inbound{
			{
				Tag:   "vless-in",
				Type:  "vless",
				Users: []config.InboundUser{{Name: "alice"}, {Name: "bob"}},
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
				Users: []config.InboundUser{{Name: "charlie"}},
				Obfs:  &config.ObfsConfig{Type: "salamander"},
			},
		},
	}

	persisted := config.EmptyPersistedCredentials()
	persisted.InboundUsers["vless-in"] = map[string]config.UserCredentials{
		"alice": {UUID: "persisted-uuid"},
	}

	credsMap, err := resolveCredentials(cfg, persisted, GenerateConfig{}, nil)
	if err != nil {
		t.Fatalf("resolveCredentials: %v", err)
	}

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
				Users: []config.InboundUser{{Name: "alice"}},
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

	credsMap, err := resolveCredentials(cfg, persisted, GenerateConfig{}, nil)
	if err != nil {
		t.Fatalf("resolveCredentials: %v", err)
	}
	vlessCreds := credsMap["vless-in"]

	if vlessCreds.Reality.PrivateKey != "persisted-priv" {
		t.Errorf("PrivateKey = %q, want persisted-priv", vlessCreds.Reality.PrivateKey)
	}
	if vlessCreds.Reality.ShortID[0] != "persisted-sid" {
		t.Errorf("ShortID[0] = %q, want persisted-sid", vlessCreds.Reality.ShortID[0])
	}
}

func TestResolveCredentialsDerivePublicKeyFromPrivate(t *testing.T) {
	t.Parallel()

	cfg := config.Config{
		Inbounds: []config.Inbound{
			{
				Tag:   "vless-in",
				Type:  "vless",
				Users: []config.InboundUser{{Name: "alice"}},
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

	priv, expectedPub, err := GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("GenerateX25519KeyPair: %v", err)
	}

	persisted := config.EmptyPersistedCredentials()
	persisted.RealityKeys["vless-in"] = config.RealityKeyPair{
		PrivateKey: priv,
		PublicKey:  "",
		ShortID:    []string{"sid"},
	}
	persisted.InboundUsers["vless-in"] = map[string]config.UserCredentials{
		"alice": {UUID: "persisted-uuid"},
	}

	credsMap, err := resolveCredentials(cfg, persisted, GenerateConfig{}, nil)
	if err != nil {
		t.Fatalf("resolveCredentials: %v", err)
	}
	vlessCreds := credsMap["vless-in"]

	if vlessCreds.Reality.PublicKey != expectedPub {
		t.Errorf("PublicKey = %q, want %q (derived from private key)", vlessCreds.Reality.PublicKey, expectedPub)
	}
}

func TestResolveCredentialsDerivePublicKeyInvalid(t *testing.T) {
	t.Parallel()

	cfg := config.Config{
		Inbounds: []config.Inbound{
			{
				Tag:   "vless-in",
				Type:  "vless",
				Users: []config.InboundUser{{Name: "alice"}},
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
		PrivateKey: "not-valid-base64",
		PublicKey:  "",
		ShortID:    []string{"sid"},
	}
	persisted.InboundUsers["vless-in"] = map[string]config.UserCredentials{
		"alice": {UUID: "persisted-uuid"},
	}

	_, err := resolveCredentials(cfg, persisted, GenerateConfig{}, nil)
	if err == nil {
		t.Fatal("expected error for invalid private key, got nil")
	}
	if !strings.Contains(err.Error(), "derive public key") {
		t.Errorf("error = %q, want it to contain 'derive public key'", err.Error())
	}
}

func TestResolveCredentialsWithPersistedObfs(t *testing.T) {
	t.Parallel()

	cfg := config.Config{
		Inbounds: []config.Inbound{
			{
				Tag:   "hy2-in",
				Type:  "hysteria2",
				Users: []config.InboundUser{{Name: "alice"}},
				Obfs:  &config.ObfsConfig{Type: "salamander"},
			},
		},
	}

	persisted := config.EmptyPersistedCredentials()
	persisted.ObfsPasswords["hy2-in"] = "persisted-obfs-pw"
	persisted.InboundUsers["hy2-in"] = map[string]config.UserCredentials{
		"alice": {Password: "persisted-pw"},
	}

	credsMap, err := resolveCredentials(cfg, persisted, GenerateConfig{}, nil)
	if err != nil {
		t.Fatalf("resolveCredentials: %v", err)
	}
	hy2Creds := credsMap["hy2-in"]

	if hy2Creds.ObfsPassword != "persisted-obfs-pw" {
		t.Errorf("ObfsPassword = %q, want persisted-obfs-pw", hy2Creds.ObfsPassword)
	}
}

func TestAddBoilerplate(t *testing.T) {
	t.Parallel()

	t.Run("default disabled", func(t *testing.T) {
		t.Parallel()
		opts := &option.Options{}
		addBoilerplate(opts, config.Config{})
		if opts.Experimental != nil {
			t.Error("Experimental should be nil when cache_file is not enabled")
		}
	})

	t.Run("explicitly enabled", func(t *testing.T) {
		t.Parallel()
		enabled := true
		opts := &option.Options{}
		addBoilerplate(opts, config.Config{
			Experimental: &config.Experimental{
				CacheFile: &config.CacheFileConfig{Enabled: &enabled},
			},
		})
		if opts.Experimental == nil {
			t.Fatal("expected Experimental to be set")
		}
		if opts.Experimental.CacheFile == nil {
			t.Fatal("expected CacheFile to be set")
		}
		if !opts.Experimental.CacheFile.Enabled {
			t.Error("CacheFile.Enabled should be true")
		}
	})

	t.Run("explicitly disabled", func(t *testing.T) {
		t.Parallel()
		disabled := false
		opts := &option.Options{}
		addBoilerplate(opts, config.Config{
			Experimental: &config.Experimental{
				CacheFile: &config.CacheFileConfig{Enabled: &disabled},
			},
		})
		if opts.Experimental != nil {
			t.Error("Experimental should be nil when cache_file is explicitly disabled")
		}
	})
}

func TestParseCertPEM(t *testing.T) {
	t.Parallel()

	certPEM, _, err := GenerateSelfSignedCertPEM("test.example.com")
	if err != nil {
		t.Fatalf("GenerateSelfSignedCertPEM: %v", err)
	}

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

func TestGenerateServerFullReset(t *testing.T) {
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
				Users:      []config.InboundUser{{Name: "alice"}, {Name: "bob"}},
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
				Users:      []config.InboundUser{{Name: "alice"}},
			},
		},
		Outbounds: []config.Outbound{
			{Type: "direct", Tag: "direct"},
		},
	}

	result2, err := GenerateServer(dir, cfg2, GenerateConfig{FullReset: true})
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

func TestGenerateServerDefaultPreservesExtraUsers(t *testing.T) {
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
				Users:      []config.InboundUser{{Name: "alice"}, {Name: "bob"}},
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
				Users:      []config.InboundUser{{Name: "alice"}},
			},
		},
		Outbounds: []config.Outbound{
			{Type: "direct", Tag: "direct"},
		},
	}

	result2, err := GenerateServer(dir, cfg2, GenerateConfig{})
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

func TestGenerateServerCompilesRuleSets(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	ruleSetSource := `{
  "rules": [
    {
      "domain_suffix": [".example.com"]
    }
  ]
}`
	if err := os.WriteFile(filepath.Join(dir, "extension.json"), []byte(ruleSetSource), 0o644); err != nil {
		t.Fatalf("write rule-set source: %v", err)
	}

	cfg := config.Config{
		Version:  1,
		Endpoint: "1.2.3.4",
		DNS: config.DNS{
			Final:   new("dns-local"),
			Servers: []config.DNSServer{{Type: "local", Tag: "dns-local"}},
		},
		Outbounds: []config.Outbound{
			{Type: "direct", Tag: "direct"},
		},
		Route: &config.Route{
			Final:          "direct",
			CustomRuleSets: []string{"extension"},
		},
	}

	result, err := GenerateServer(dir, cfg, GenerateConfig{})
	if err != nil {
		t.Fatalf("GenerateServer: %v", err)
	}

	srsFile := findFile(result.Files, "rule-set/extension.srs")
	if srsFile == nil {
		t.Fatal("rule-set/extension.srs not in result files")
	}
	if len(srsFile.Content) == 0 {
		t.Fatal("rule-set/extension.srs is empty")
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

func TestGenerateAll(t *testing.T) {
	t.Parallel()

	projectRoot := t.TempDir()

	setupTestServer(t, projectRoot, "exit-server", config.Config{
		Version:  1,
		Endpoint: "10.0.0.1:443",
		DNS: config.DNS{
			Final:   new("dns-local"),
			Servers: []config.DNSServer{{Type: "local", Tag: "dns-local"}},
		},
		Inbounds: []config.Inbound{
			{
				Tag:        "vless-in",
				Type:       inboundTypeVLESS,
				ListenPort: 443,
				Users:      []config.InboundUser{{Name: "proxy-server"}},
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
		Outbounds: []config.Outbound{
			{Type: outboundTypeDirect, Tag: "direct"},
		},
	})

	setupTestServer(t, projectRoot, "proxy-server", config.Config{
		Version: 1,
		DNS: config.DNS{
			Final:   new("dns-local"),
			Servers: []config.DNSServer{{Type: "local", Tag: "dns-local"}},
		},
		Outbounds: []config.Outbound{
			{Type: outboundTypeDirect, Tag: "direct"},
			{
				Type:    inboundTypeVLESS,
				Tag:     "exit-vless",
				Server:  "exit-server",
				Inbound: "vless-in",
				User:    "proxy-server",
			},
		},
	})

	results, err := GenerateAll(projectRoot, "lib", GenerateConfig{})
	if err != nil {
		t.Fatalf("GenerateAll: %v", err)
	}

	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}

	exitResult := findResultByName(results, "exit-server")
	if exitResult == nil {
		t.Fatal("exit-server result not found")
	}

	proxyResult := findResultByName(results, "proxy-server")
	if proxyResult == nil {
		t.Fatal("proxy-server result not found")
	}

	exitConfig := findFile(exitResult.Files, "config.json")
	if exitConfig == nil {
		t.Fatal("exit-server config.json not found")
	}

	var exitParsed map[string]any
	if err := json.Unmarshal(exitConfig.Content, &exitParsed); err != nil {
		t.Fatalf("parse exit config: %v", err)
	}

	exitInbounds, ok := exitParsed["inbounds"].([]any)
	if !ok || len(exitInbounds) != 1 {
		t.Fatalf("expected 1 inbound on exit-server, got %d", len(exitInbounds))
	}

	proxyConfig := findFile(proxyResult.Files, "config.json")
	if proxyConfig == nil {
		t.Fatal("proxy-server config.json not found")
	}

	var proxyParsed map[string]any
	if err := json.Unmarshal(proxyConfig.Content, &proxyParsed); err != nil {
		t.Fatalf("parse proxy config: %v", err)
	}

	proxyOutbounds, ok := proxyParsed["outbounds"].([]any)
	if !ok {
		t.Fatal("proxy-server has no outbounds")
	}

	foundVlessOut := false
	for _, ob := range proxyOutbounds {
		obMap, ok := ob.(map[string]any)
		if !ok {
			continue
		}
		if obMap["type"] == "vless" {
			foundVlessOut = true
		}
	}
	if !foundVlessOut {
		t.Error("proxy-server should have a vless outbound")
	}
}

func TestGenerateAllEmpty(t *testing.T) {
	t.Parallel()

	projectRoot := t.TempDir()

	results, err := GenerateAll(projectRoot, "lib", GenerateConfig{})
	if err != nil {
		t.Fatalf("GenerateAll: %v", err)
	}
	if results != nil {
		t.Errorf("expected nil results for empty project, got %d", len(results))
	}
}

func TestGenerateAllCycle(t *testing.T) {
	t.Parallel()

	projectRoot := t.TempDir()

	setupTestServer(t, projectRoot, "srv-a", config.Config{
		Version: 1,
		DNS: config.DNS{
			Final:   new("dns-local"),
			Servers: []config.DNSServer{{Type: "local", Tag: "dns-local"}},
		},
		Outbounds: []config.Outbound{
			{Type: inboundTypeVLESS, Tag: "out", Server: "srv-b", Inbound: "vless-in"},
		},
	})

	setupTestServer(t, projectRoot, "srv-b", config.Config{
		Version: 1,
		DNS: config.DNS{
			Final:   new("dns-local"),
			Servers: []config.DNSServer{{Type: "local", Tag: "dns-local"}},
		},
		Outbounds: []config.Outbound{
			{Type: inboundTypeVLESS, Tag: "out", Server: "srv-a", Inbound: "vless-in"},
		},
	})

	_, err := GenerateAll(projectRoot, "lib", GenerateConfig{})
	if err == nil {
		t.Fatal("expected error for cycle")
	}
}

func findResultByName(results []GenerateResult, server string) *GenerateResult {
	for i := range results {
		if results[i].Server == server {
			return &results[i]
		}
	}
	return nil
}

func TestCrossServerUserRefs(t *testing.T) {
	t.Parallel()

	configs := map[string]config.Config{
		"exit-server": {
			Inbounds: []config.Inbound{
				{Tag: "vless-in", Type: inboundTypeVLESS, Users: []config.InboundUser{{Name: "declared-user"}}},
			},
		},
		"proxy-a": {
			Outbounds: []config.Outbound{
				{Type: inboundTypeVLESS, Tag: "out1", Server: "exit-server", Inbound: "vless-in", User: "proxy-a"},
			},
		},
		"proxy-b": {
			Outbounds: []config.Outbound{
				{Type: inboundTypeVLESS, Tag: "out1", Server: "exit-server", Inbound: "vless-in"},
			},
		},
		"unrelated": {
			Outbounds: []config.Outbound{
				{Type: outboundTypeDirect, Tag: "direct"},
			},
		},
	}

	refs := crossServerUserRefs(configs)

	exitRefs := refs["exit-server"]
	if exitRefs == nil {
		t.Fatal("expected refs for exit-server")
	}

	vlessRefs := exitRefs["vless-in"]
	if vlessRefs == nil {
		t.Fatal("expected refs for vless-in tag")
	}

	if !vlessRefs["proxy-a"] {
		t.Error("expected proxy-a to be referenced")
	}
	if !vlessRefs["proxy-b"] {
		t.Error("expected proxy-b to be referenced (default user = source server name)")
	}
	if len(vlessRefs) != 2 {
		t.Errorf("expected 2 referenced users, got %d", len(vlessRefs))
	}

	if refs["unrelated"] != nil {
		t.Error("unrelated server should have no cross-server refs")
	}
}

func TestResolveCredentialsFullResetRegeneratesAll(t *testing.T) {
	t.Parallel()

	cfg := config.Config{
		Inbounds: []config.Inbound{
			{
				Tag:   "vless-in",
				Type:  "vless",
				Users: []config.InboundUser{{Name: "alice"}},
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
				Users: []config.InboundUser{{Name: "bob"}},
				Obfs:  &config.ObfsConfig{Type: "salamander"},
			},
		},
	}

	persisted := config.EmptyPersistedCredentials()
	persisted.InboundUsers["vless-in"] = map[string]config.UserCredentials{
		"alice": {UUID: "old-uuid", Flow: "xtls-rprx-vision"},
	}
	persisted.RealityKeys["vless-in"] = config.RealityKeyPair{
		PrivateKey: "old-priv",
		PublicKey:  "old-pub",
		ShortID:    []string{"old-sid"},
	}
	persisted.InboundUsers["hy2-in"] = map[string]config.UserCredentials{
		"bob": {Password: "old-pw"},
	}
	persisted.ObfsPasswords["hy2-in"] = "old-obfs"

	credsMap, err := resolveCredentials(cfg, persisted, GenerateConfig{FullReset: true}, nil)
	if err != nil {
		t.Fatalf("resolveCredentials: %v", err)
	}

	vlessCreds := credsMap["vless-in"]
	if vlessCreds.Users["alice"].UUID == "old-uuid" {
		t.Error("FullReset should regenerate UUID, but got persisted value")
	}
	if vlessCreds.Users["alice"].UUID == "" {
		t.Error("FullReset should generate a new UUID")
	}
	if vlessCreds.Reality != nil && vlessCreds.Reality.PrivateKey == "old-priv" {
		t.Error("FullReset should regenerate reality keys")
	}

	hy2Creds := credsMap["hy2-in"]
	if hy2Creds.Users["bob"].Password == "old-pw" {
		t.Error("FullReset should regenerate password, but got persisted value")
	}
	if hy2Creds.ObfsPassword == "old-obfs" {
		t.Error("FullReset should regenerate obfs password")
	}
}

func TestResolveCredentialsOrphanRemovesUnreferencedUsers(t *testing.T) {
	t.Parallel()

	cfg := config.Config{
		Inbounds: []config.Inbound{
			{
				Tag:   "vless-in",
				Type:  "vless",
				Users: []config.InboundUser{{Name: "alice"}},
			},
		},
	}

	persisted := config.EmptyPersistedCredentials()
	persisted.InboundUsers["vless-in"] = map[string]config.UserCredentials{
		"alice":        {UUID: "alice-uuid"},
		"proxy-server": {UUID: "proxy-uuid"},
		"stale-server": {UUID: "stale-uuid"},
	}

	crossServerUsers := map[string]map[string]bool{
		"vless-in": {"proxy-server": true},
	}

	credsMap, err := resolveCredentials(cfg, persisted, GenerateConfig{Orphan: true}, crossServerUsers)
	if err != nil {
		t.Fatalf("resolveCredentials: %v", err)
	}

	vlessCreds := credsMap["vless-in"]

	if vlessCreds.Users["alice"].UUID != "alice-uuid" {
		t.Errorf("alice UUID = %q, want alice-uuid (declared user should be preserved)", vlessCreds.Users["alice"].UUID)
	}
	if vlessCreds.Users["proxy-server"].UUID != "proxy-uuid" {
		t.Errorf("proxy-server UUID = %q, want proxy-uuid (referenced user should be preserved)",
			vlessCreds.Users["proxy-server"].UUID)
	}
	if _, exists := vlessCreds.Users["stale-server"]; exists {
		t.Error("stale-server should be removed as an orphan (not declared, not referenced)")
	}
	if len(vlessCreds.Users) != 2 {
		t.Errorf("expected 2 users (alice + proxy-server), got %d", len(vlessCreds.Users))
	}
}

func TestResolveCredentialsOrphanPreservesCreds(t *testing.T) {
	t.Parallel()

	cfg := config.Config{
		Inbounds: []config.Inbound{
			{
				Tag:   "vless-in",
				Type:  "vless",
				Users: []config.InboundUser{{Name: "alice"}},
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
	persisted.InboundUsers["vless-in"] = map[string]config.UserCredentials{
		"alice": {UUID: "alice-uuid", Flow: "xtls-rprx-vision"},
	}
	persisted.RealityKeys["vless-in"] = config.RealityKeyPair{
		PrivateKey: "persisted-priv",
		PublicKey:  "persisted-pub",
		ShortID:    []string{"persisted-sid"},
	}

	credsMap, err := resolveCredentials(cfg, persisted, GenerateConfig{Orphan: true}, nil)
	if err != nil {
		t.Fatalf("resolveCredentials: %v", err)
	}

	vlessCreds := credsMap["vless-in"]
	if vlessCreds.Users["alice"].UUID != "alice-uuid" {
		t.Errorf(
			"alice UUID = %q, want alice-uuid (orphan mode should preserve credentials)",
			vlessCreds.Users["alice"].UUID,
		)
	}
	if vlessCreds.Reality.PrivateKey != "persisted-priv" {
		t.Errorf("Reality PrivateKey = %q, want persisted-priv", vlessCreds.Reality.PrivateKey)
	}
}

func setupTestServer(t *testing.T, root string, name string, cfg config.Config) {
	t.Helper()
	dir := filepath.Join(root, name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "cheburbox.json"), data, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
}
