package generate

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/Arsolitt/cheburbox/config"
)

func TestIntegrationFullGeneration(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	cfg := config.Config{
		Version:  1,
		Endpoint: "138.124.181.194",
		Log:      json.RawMessage(`{"level": "error", "timestamp": true}`),
		DNS: config.DNS{
			Final:    new("dns-remote"),
			Strategy: new("prefer_ipv4"),
			Servers: []config.DNSServer{
				{Type: "local", Tag: "dns-local"},
				{Type: "tls", Tag: "dns-remote", Server: "8.8.8.8", ServerPort: 853, Detour: "direct"},
			},
			Rules: json.RawMessage(`[{"action": "route", "server": "dns-local"}]`),
		},
		Inbounds: []config.Inbound{
			{
				Tag:        "vless-in",
				Type:       "vless",
				ListenPort: 443,
				TLS: &config.InboundTLS{
					Reality: &config.RealityConfig{
						Handshake: &config.RealityHandshake{
							Server:     "spain.info",
							ServerPort: 443,
						},
					},
				},
				Users: []config.InboundUser{{Name: "desktop"}, {Name: "Laptop"}},
			},
			{
				Tag:        "hy2-in",
				Type:       "hysteria2",
				ListenPort: 443,
				UpMbps:     1000,
				DownMbps:   1000,
				TLS:        &config.InboundTLS{ServerName: "spain.info"},
				Obfs:       &config.ObfsConfig{Type: "salamander"},
				Masq: &config.MasqueradeConfig{
					Type:        "proxy",
					URL:         "https://spain.info",
					RewriteHost: true,
				},
				Users: []config.InboundUser{{Name: "desktop"}},
			},
			{
				Tag:                    "tun-in",
				Type:                   "tun",
				InterfaceName:          "sing-box",
				Address:                []string{"172.19.0.1/30"},
				MTU:                    1500,
				AutoRoute:              true,
				Stack:                  "system",
				EndpointIndependentNAT: true,
				ExcludeInterface:       []string{"wt0"},
				RouteExcludeAddress:    []string{"10.0.0.0/8"},
			},
		},
		Outbounds: []config.Outbound{
			{Type: "direct", Tag: "direct"},
			{
				Type:      "urltest",
				Tag:       "proxy",
				Outbounds: []string{"vless-ref", "hy2-ref"},
				URL:       "https://www.gstatic.com/generate_204",
				Interval:  "3m",
			},
		},
		Route: &config.Route{
			Final:               "direct",
			AutoDetectInterface: true,
			CustomRuleSets:      []string{"extension"},
		},
	}

	result, err := GenerateServer(dir, cfg, GenerateConfig{})
	if err != nil {
		t.Fatalf("GenerateServer: %v", err)
	}

	configFile := findFile(result.Files, "config.json")
	if configFile == nil {
		t.Fatal("config.json not in result")
	}

	var parsed map[string]any
	if err := json.Unmarshal(configFile.Content, &parsed); err != nil {
		t.Fatalf("parse config.json: %v", err)
	}

	inbounds, ok := parsed["inbounds"].([]any)
	if !ok || len(inbounds) != 3 {
		t.Fatalf("expected 3 inbounds, got %d", len(inbounds))
	}

	outbounds, ok := parsed["outbounds"].([]any)
	if !ok || len(outbounds) != 2 {
		t.Fatalf("expected 2 outbounds, got %d", len(outbounds))
	}

	certFile := findFile(result.Files, "certs/spain.info.crt")
	if certFile == nil {
		t.Fatal("certs/spain.info.crt not in result (hysteria2 with TLS should generate cert)")
	}
	keyFile := findFile(result.Files, "certs/spain.info.key")
	if keyFile == nil {
		t.Fatal("certs/spain.info.key not in result")
	}
}

func TestIntegrationIdempotentGeneration(t *testing.T) {
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

	for i := range 3 {
		result, err := GenerateServer(dir, cfg, GenerateConfig{})
		if err != nil {
			t.Fatalf("generate iteration %d: %v", i, err)
		}

		for _, f := range result.Files {
			if err := os.WriteFile(filepath.Join(dir, f.Path), f.Content, 0o644); err != nil {
				t.Fatalf("write %s: %v", f.Path, err)
			}
		}
	}

	data, _ := os.ReadFile(filepath.Join(dir, "config.json"))
	var parsed map[string]any
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("parse: %v", err)
	}

	inbounds, ok := parsed["inbounds"].([]any)
	if !ok || len(inbounds) != 1 {
		t.Fatalf("expected 1 inbound, got %d", len(inbounds))
	}

	firstIn := inbounds[0].(map[string]any)
	users := firstIn["users"].([]any)
	if len(users) != 1 {
		t.Fatalf("expected 1 user, got %d (extra users accumulated)", len(users))
	}
}

func TestIntegrationMultiServerCrossServer(t *testing.T) {
	t.Parallel()

	projectRoot := t.TempDir()

	exitDir := filepath.Join(projectRoot, "exit-server")
	if err := os.MkdirAll(exitDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	exitCfg := config.Config{
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
			{
				Tag:        "hy2-in",
				Type:       inboundTypeHysteria2,
				ListenPort: 8443,
				TLS:        &config.InboundTLS{ServerName: "hy.example.com"},
				Users:      []config.InboundUser{{Name: "proxy-server"}},
			},
		},
		Outbounds: []config.Outbound{
			{Type: outboundTypeDirect, Tag: "direct"},
		},
	}
	exitData, _ := json.Marshal(exitCfg)
	if err := os.WriteFile(filepath.Join(exitDir, "cheburbox.json"), exitData, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	proxyDir := filepath.Join(projectRoot, "proxy-server")
	if err := os.MkdirAll(proxyDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	proxyCfg := config.Config{
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
			{
				Type:    inboundTypeHysteria2,
				Tag:     "exit-hy",
				Server:  "exit-server",
				Inbound: "hy2-in",
				User:    "proxy-server",
			},
		},
	}
	proxyData, _ := json.Marshal(proxyCfg)
	if err := os.WriteFile(filepath.Join(proxyDir, "cheburbox.json"), proxyData, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

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
	if !ok {
		t.Fatal("exit-server has no inbounds")
	}
	if len(exitInbounds) != 2 {
		t.Fatalf("expected 2 inbounds on exit-server, got %d", len(exitInbounds))
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

	vlessFound := false
	hy2Found := false
	for _, ob := range proxyOutbounds {
		obMap, ok := ob.(map[string]any)
		if !ok {
			continue
		}
		if obMap["type"] == "vless" {
			vlessFound = true
		}
		if obMap["type"] == "hysteria2" {
			hy2Found = true
		}
	}
	if !vlessFound {
		t.Error("proxy-server should have a vless outbound")
	}
	if !hy2Found {
		t.Error("proxy-server should have a hysteria2 outbound")
	}
}
