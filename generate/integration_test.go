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
			Rules: json.RawMessage(`[{"action": "sniff"}]`),
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
				Users: []string{"desktop", "Laptop"},
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
				Users: []string{"desktop"},
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
				Users:      []string{"alice"},
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
