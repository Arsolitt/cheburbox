package config

import (
	"encoding/json"
	"testing"
)

func TestConfigUnmarshal(t *testing.T) {
	raw := `{
		"version": 1,
		"endpoint": "138.124.181.194",
		"log": {"level": "error", "timestamp": true},
		"dns": {
			"servers": [
				{"type": "local", "tag": "dns-local"},
				{"type": "tls", "tag": "dns-remote", "server": "8.8.8.8", "server_port": 853, "detour": "direct"}
			],
			"final": "dns-remote",
			"strategy": "prefer_ipv4"
		},
		"inbounds": [
			{
				"tag": "vless-in",
				"type": "vless",
				"listen_port": 443,
				"tls": {
					"reality": {
						"handshake": {"server": "spain.info", "server_port": 443},
						"short_id": ["9b1f10c4"]
					}
				},
				"users": ["desktop", "Laptop", "Mobile"]
			},
			{
				"tag": "hy2-in",
				"type": "hysteria2",
				"listen_port": 443,
				"up_mbps": 1000,
				"down_mbps": 1000,
				"tls": {"server_name": "spain.info"},
				"obfs": {"type": "salamander"},
				"masquerade": {"type": "proxy", "url": "https://spain.info", "rewrite_host": true},
				"users": ["desktop"]
			},
			{
				"tag": "tun-in",
				"type": "tun",
				"interface_name": "sing-box",
				"address": ["172.19.0.1/30"],
				"mtu": 1500,
				"auto_route": true,
				"stack": "system",
				"endpoint_independent_nat": true,
				"exclude_interface": ["wt0", "awg0"],
				"route_exclude_address": ["10.0.0.0/8"]
			}
		],
		"outbounds": [
			{"type": "direct", "tag": "direct"},
			{
				"type": "vless",
				"tag": "sp-p-2-vless",
				"server": "sp-p-2",
				"inbound": "vless-in",
				"user": "ru-p-2",
				"flow": "xtls-rprx-vision",
				"endpoint": "1.2.3.4"
			},
			{
				"type": "hysteria2",
				"tag": "sp-p-2-hy",
				"server": "sp-p-2",
				"inbound": "hy2-in",
				"user": "ru-p-2"
			},
			{
				"type": "urltest",
				"tag": "proxy",
				"outbounds": ["sp-p-2-vless", "sp-p-2-hy"],
				"url": "https://www.gstatic.com/generate_204",
				"interval": "3m"
			},
			{
				"type": "selector",
				"tag": "manual-proxy",
				"outbounds": ["sp-p-2-vless", "sp-p-2-hy"]
			}
		],
		"route": {
			"final": "direct",
			"auto_detect_interface": true,
			"custom_rule_sets": ["extension", "fastly"],
			"rules": [
				{
					"action": "sniff"
				}
			]
		}
	}`

	var cfg Config
	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	if cfg.Version != 1 {
		t.Errorf("Version = %d, want 1", cfg.Version)
	}
	if cfg.Endpoint != "138.124.181.194" {
		t.Errorf("Endpoint = %q, want %q", cfg.Endpoint, "138.124.181.194")
	}
	if len(cfg.DNS.Servers) != 2 {
		t.Fatalf("DNS.Servers count = %d, want 2", len(cfg.DNS.Servers))
	}
	if cfg.DNS.Servers[0].Tag != "dns-local" {
		t.Errorf("DNS.Servers[0].Tag = %q, want %q", cfg.DNS.Servers[0].Tag, "dns-local")
	}
	if len(cfg.Inbounds) != 3 {
		t.Fatalf("Inbounds count = %d, want 3", len(cfg.Inbounds))
	}
	if cfg.Inbounds[0].Type != "vless" {
		t.Errorf("Inbounds[0].Type = %q, want %q", cfg.Inbounds[0].Type, "vless")
	}
	if len(cfg.Outbounds) != 5 {
		t.Fatalf("Outbounds count = %d, want 5", len(cfg.Outbounds))
	}
	if cfg.Outbounds[3].Type != "urltest" {
		t.Errorf("Outbounds[3].Type = %q, want %q", cfg.Outbounds[3].Type, "urltest")
	}
	if cfg.Outbounds[4].Type != "selector" {
		t.Errorf("Outbounds[4].Type = %q, want %q", cfg.Outbounds[4].Type, "selector")
	}
	if cfg.Route.Final != "direct" {
		t.Errorf("Route.Final = %q, want %q", cfg.Route.Final, "direct")
	}
	if len(cfg.Route.CustomRuleSets) != 2 {
		t.Errorf("Route.CustomRuleSets count = %d, want 2", len(cfg.Route.CustomRuleSets))
	}
}

func TestConfigMarshalRoundTrip(t *testing.T) {
	cfg := Config{
		Version:  1,
		Endpoint: "1.2.3.4",
		DNS: DNS{
			Servers:  []DNSServer{{Type: "local", Tag: "dns-local"}},
			Final:    new("dns-local"),
			Strategy: new("prefer_ipv4"),
		},
	}

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	var cfg2 Config
	if err := json.Unmarshal(data, &cfg2); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	if cfg2.Version != cfg.Version {
		t.Errorf("round-trip Version = %d, want %d", cfg2.Version, cfg.Version)
	}
	if cfg2.DNS.Final == nil || *cfg2.DNS.Final != "dns-local" {
		t.Errorf("round-trip DNS.Final = %v, want dns-local", cfg2.DNS.Final)
	}
	if cfg2.DNS.Strategy == nil || *cfg2.DNS.Strategy != "prefer_ipv4" {
		t.Errorf("round-trip DNS.Strategy = %v, want prefer_ipv4", cfg2.DNS.Strategy)
	}
	if cfg2.Endpoint != cfg.Endpoint {
		t.Errorf("round-trip Endpoint = %q, want %q", cfg2.Endpoint, cfg.Endpoint)
	}
}

func strPtr(s string) *string {
	return new(s)
}
