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
				"users": [{"name": "desktop"}, {"name": "Laptop"}, {"name": "Mobile"}]
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
				"users": [{"name": "desktop"}]
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

func TestConfigMultiplexFields(t *testing.T) {
	t.Parallel()

	raw := `{
		"version": 1,
		"endpoint": "1.2.3.4",
		"dns": {"servers": [{"type": "local", "tag": "dns-local"}]},
		"inbounds": [
			{
				"tag": "vless-in",
				"type": "vless",
				"listen_port": 443,
				"multiplex": {
					"enabled": true,
					"padding": true,
					"brutal": {"enabled": true, "up_mbps": 100, "down_mbps": 100}
				},
				"users": [{"name": "alice"}]
			}
		],
		"outbounds": [
			{
				"type": "vless",
				"tag": "to-a",
				"server": "srv-a",
				"inbound": "vless-in",
				"multiplex": {
					"enabled": true,
					"protocol": "smux",
					"max_connections": 4,
					"min_streams": 1,
					"padding": false
				}
			},
			{"type": "direct", "tag": "direct"}
		]
	}`

	var cfg Config
	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	in := cfg.Inbounds[0]
	if in.Multiplex == nil {
		t.Fatal("Inbound.Multiplex is nil")
	}
	if !in.Multiplex.Enabled {
		t.Error("Inbound.Multiplex.Enabled = false, want true")
	}
	if !in.Multiplex.Padding {
		t.Error("Inbound.Multiplex.Padding = false, want true")
	}
	if in.Multiplex.Brutal == nil || !in.Multiplex.Brutal.Enabled {
		t.Fatal("Inbound.Multiplex.Brutal not enabled")
	}
	if in.Multiplex.Brutal.UpMbps != 100 {
		t.Errorf("Inbound.Multiplex.Brutal.UpMbps = %d, want 100", in.Multiplex.Brutal.UpMbps)
	}

	out := cfg.Outbounds[0]
	if out.Multiplex == nil {
		t.Fatal("Outbound.Multiplex is nil")
	}
	if !out.Multiplex.Enabled {
		t.Error("Outbound.Multiplex.Enabled = false, want true")
	}
	if out.Multiplex.Protocol != "smux" {
		t.Errorf("Outbound.Multiplex.Protocol = %q, want smux", out.Multiplex.Protocol)
	}
	if out.Multiplex.MaxConnections != 4 {
		t.Errorf("Outbound.Multiplex.MaxConnections = %d, want 4", out.Multiplex.MaxConnections)
	}
	if out.Multiplex.MinStreams != 1 {
		t.Errorf("Outbound.Multiplex.MinStreams = %d, want 1", out.Multiplex.MinStreams)
	}
}

func TestConfigAmneziaWGRoundTrip(t *testing.T) {
	t.Parallel()

	cfg := Config{
		Version:  1,
		Endpoint: "10.0.0.1",
		DNS: DNS{
			Servers: []DNSServer{{Type: "local", Tag: "dns-local"}},
		},
		Inbounds: []Inbound{
			{
				Tag:        "awg-in",
				Type:       "amneziawg",
				ListenPort: 51820,
				Address:    []string{"10.0.0.1/24"},
				MTU:        1280,
				Amnezia: &AmneziaConfig{
					Protocol: "quic",
					Preset:   "home-balanced",
					MTU:      1280,
				},
			},
		},
		Outbounds: []Outbound{
			{
				Type:    "amneziawg",
				Tag:     "awg-out",
				Server:  "exit-server",
				Inbound: "awg-in",
				Address: []string{"10.0.0.5/32"},
				MTU:     1280,
			},
			{Type: "direct", Tag: "direct"},
		},
		Route: &Route{
			Final:               "direct",
			AutoDetectInterface: true,
		},
	}

	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	var cfg2 Config
	if err := json.Unmarshal(data, &cfg2); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	in := cfg2.Inbounds[0]
	if in.Type != "amneziawg" {
		t.Errorf("inbound Type = %q, want amneziawg", in.Type)
	}
	if in.ListenPort != 51820 {
		t.Errorf("inbound ListenPort = %d, want 51820", in.ListenPort)
	}
	if len(in.Address) != 1 || in.Address[0] != "10.0.0.1/24" {
		t.Errorf("inbound Address = %v, want [10.0.0.1/24]", in.Address)
	}
	if in.MTU != 1280 {
		t.Errorf("inbound MTU = %d, want 1280", in.MTU)
	}
	if in.Amnezia == nil {
		t.Fatal("inbound Amnezia is nil after round-trip")
	}
	if in.Amnezia.Protocol != "quic" {
		t.Errorf("inbound Amnezia.Protocol = %q, want quic", in.Amnezia.Protocol)
	}
	if in.Amnezia.MTU != 1280 {
		t.Errorf("inbound Amnezia.MTU = %d, want 1280", in.Amnezia.MTU)
	}
	if in.Amnezia.Preset != "home-balanced" {
		t.Errorf("inbound Amnezia.Preset = %q, want home-balanced", in.Amnezia.Preset)
	}

	out := cfg2.Outbounds[0]
	if out.Type != "amneziawg" {
		t.Errorf("outbound Type = %q, want amneziawg", out.Type)
	}
	if out.Server != "exit-server" {
		t.Errorf("outbound Server = %q, want exit-server", out.Server)
	}
	if out.Inbound != "awg-in" {
		t.Errorf("outbound Inbound = %q, want awg-in", out.Inbound)
	}
	if len(out.Address) != 1 || out.Address[0] != "10.0.0.5/32" {
		t.Errorf("outbound Address = %v, want [10.0.0.5/32]", out.Address)
	}
	if out.MTU != 1280 {
		t.Errorf("outbound MTU = %d, want 1280", out.MTU)
	}
}
