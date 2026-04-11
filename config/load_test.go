package config

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func TestDiscover(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		setup   func(t *testing.T, root string)
		want    []string
		wantErr bool
	}{
		{
			name: "finds directories with cheburbox.json",
			setup: func(t *testing.T, root string) {
				t.Helper()
				mustMkdirAll(t, filepath.Join(root, "server-a"))
				mustWriteFile(t, filepath.Join(root, "server-a", "cheburbox.json"), `{"version":1}`)
				mustMkdirAll(t, filepath.Join(root, "server-b"))
				mustWriteFile(t, filepath.Join(root, "server-b", "cheburbox.json"), `{"version":1}`)
			},
			want: []string{"server-a", "server-b"},
		},
		{
			name: "finds directories with dot cheburbox jsonnet",
			setup: func(t *testing.T, root string) {
				t.Helper()
				mustMkdirAll(t, filepath.Join(root, "server-c"))
				mustWriteFile(t, filepath.Join(root, "server-c", ".cheburbox.jsonnet"), `{"version":1}`)
			},
			want: []string{"server-c"},
		},
		{
			name: "skips directories without config files",
			setup: func(t *testing.T, root string) {
				t.Helper()
				mustMkdirAll(t, filepath.Join(root, "server-a"))
				mustWriteFile(t, filepath.Join(root, "server-a", "cheburbox.json"), `{"version":1}`)
				mustMkdirAll(t, filepath.Join(root, "empty-dir"))
			},
			want: []string{"server-a"},
		},
		{
			name: "skips nested directories",
			setup: func(t *testing.T, root string) {
				t.Helper()
				mustMkdirAll(t, filepath.Join(root, "server-a"))
				mustWriteFile(t, filepath.Join(root, "server-a", "cheburbox.json"), `{"version":1}`)
				mustMkdirAll(t, filepath.Join(root, "server-a", "nested"))
				mustWriteFile(t, filepath.Join(root, "server-a", "nested", "cheburbox.json"), `{"version":1}`)
			},
			want: []string{"server-a"},
		},
		{
			name: "dot cheburbox jsonnet takes precedence but both listed once",
			setup: func(t *testing.T, root string) {
				t.Helper()
				mustMkdirAll(t, filepath.Join(root, "server-a"))
				mustWriteFile(t, filepath.Join(root, "server-a", ".cheburbox.jsonnet"), `{"version":1}`)
				mustWriteFile(t, filepath.Join(root, "server-a", "cheburbox.json"), `{"version":1}`)
			},
			want: []string{"server-a"},
		},
		{
			name:  "empty project root returns empty list",
			setup: func(t *testing.T, _ string) { t.Helper() },
			want:  []string{},
		},
		{
			name:    "nonexistent root returns error",
			setup:   func(t *testing.T, _ string) { t.Helper() },
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			root := t.TempDir()

			if tt.wantErr {
				_, err := Discover(filepath.Join(root, "nonexistent"))
				if err == nil {
					t.Fatal("expected error for nonexistent root")
				}
				return
			}

			tt.setup(t, root)
			got, err := Discover(root)
			if err != nil {
				t.Fatalf("Discover() error = %v", err)
			}
			sort.Strings(got)
			sort.Strings(tt.want)
			if len(got) != len(tt.want) {
				t.Fatalf("Discover() = %v, want %v", got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("Discover()[%d] = %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func mustMkdirAll(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatalf("mkdirall %s: %v", path, err)
	}
}

func mustWriteFile(t *testing.T, path string, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("writefile %s: %v", path, err)
	}
}

func TestLoadServer(t *testing.T) {
	t.Parallel()

	tests := []struct {
		setup   func(t *testing.T, dir string)
		check   func(t *testing.T, cfg Config)
		name    string
		wantErr bool
	}{
		{
			name: "loads valid cheburbox.json",
			setup: func(t *testing.T, dir string) {
				t.Helper()
				mustWriteFile(t, filepath.Join(dir, "cheburbox.json"), `{
					"version": 1,
					"endpoint": "1.2.3.4",
					"dns": {
						"servers": [{"type": "local", "tag": "dns-local"}],
						"final": "dns-local"
					}
				}`)
			},
			check: func(t *testing.T, cfg Config) {
				t.Helper()
				if cfg.Version != 1 {
					t.Errorf("Version = %d, want 1", cfg.Version)
				}
				if cfg.Endpoint != "1.2.3.4" {
					t.Errorf("Endpoint = %q, want %q", cfg.Endpoint, "1.2.3.4")
				}
				if len(cfg.DNS.Servers) != 1 {
					t.Errorf("DNS.Servers count = %d, want 1", len(cfg.DNS.Servers))
				}
			},
		},
		{
			name:    "error on missing cheburbox.json",
			setup:   func(t *testing.T, _ string) { t.Helper() },
			wantErr: true,
		},
		{
			name: "error on invalid JSON",
			setup: func(t *testing.T, dir string) {
				t.Helper()
				mustWriteFile(t, filepath.Join(dir, "cheburbox.json"), `{not valid json}`)
			},
			wantErr: true,
		},
		{
			name: "error on missing version field",
			setup: func(t *testing.T, dir string) {
				t.Helper()
				mustWriteFile(t, filepath.Join(dir, "cheburbox.json"), `{
					"dns": {"servers": []}
				}`)
			},
			wantErr: true,
		},
		{
			name: "loads config with inbounds and outbounds",
			setup: func(t *testing.T, dir string) {
				t.Helper()
				mustWriteFile(t, filepath.Join(dir, "cheburbox.json"), `{
					"version": 1,
					"dns": {
						"servers": [{"type": "local", "tag": "dns-local"}],
						"final": "dns-local"
					},
					"inbounds": [
						{"tag": "vless-in", "type": "vless", "listen_port": 443, "users": [{"name": "alice"}]}
					],
					"outbounds": [
						{"type": "direct", "tag": "direct"}
					]
				}`)
			},
			check: func(t *testing.T, cfg Config) {
				t.Helper()
				if len(cfg.Inbounds) != 1 {
					t.Fatalf("Inbounds count = %d, want 1", len(cfg.Inbounds))
				}
				if cfg.Inbounds[0].Tag != "vless-in" {
					t.Errorf("Inbounds[0].Tag = %q, want %q", cfg.Inbounds[0].Tag, "vless-in")
				}
				if len(cfg.Outbounds) != 1 {
					t.Fatalf("Outbounds count = %d, want 1", len(cfg.Outbounds))
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			tt.setup(t, dir)

			cfg, err := loadServer(dir)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.check != nil {
				tt.check(t, cfg)
			}
		})
	}
}

func TestLoadServerJsonnet(t *testing.T) {
	t.Parallel()

	tests := []struct {
		setup   func(t *testing.T, root, dir string)
		check   func(t *testing.T, cfg Config)
		name    string
		wantErr bool
	}{
		{
			name: "evaluates simple jsonnet",
			setup: func(t *testing.T, _, dir string) {
				t.Helper()
				mustWriteFile(t, filepath.Join(dir, ".cheburbox.jsonnet"), `
{
	version: 1,
	endpoint: "5.6.7.8",
	dns: {
		servers: [{type: "local", tag: "dns-local"}],
		final: "dns-local",
	},
}
`)
			},
			check: func(t *testing.T, cfg Config) {
				t.Helper()
				if cfg.Version != 1 {
					t.Errorf("Version = %d, want 1", cfg.Version)
				}
				if cfg.Endpoint != "5.6.7.8" {
					t.Errorf("Endpoint = %q, want %q", cfg.Endpoint, "5.6.7.8")
				}
			},
		},
		{
			name: "jsonnet with jpath imports",
			setup: func(t *testing.T, root, dir string) {
				t.Helper()
				libDir := filepath.Join(root, "lib")
				mustMkdirAll(t, libDir)
				mustWriteFile(t, filepath.Join(libDir, "dns.jsonnet"), `
{
	servers: [{type: "local", tag: "dns-local"}],
	final: "dns-local",
	strategy: "prefer_ipv4",
}
`)
				mustWriteFile(t, filepath.Join(dir, ".cheburbox.jsonnet"), `
local dns = import "lib/dns.jsonnet";
{
	version: 1,
	endpoint: "9.8.7.6",
	dns: dns,
}
`)
			},
			check: func(t *testing.T, cfg Config) {
				t.Helper()
				if len(cfg.DNS.Servers) != 1 {
					t.Fatalf("DNS.Servers count = %d, want 1", len(cfg.DNS.Servers))
				}
				if cfg.DNS.Servers[0].Tag != "dns-local" {
					t.Errorf("DNS.Servers[0].Tag = %q, want %q", cfg.DNS.Servers[0].Tag, "dns-local")
				}
				if cfg.DNS.Strategy == nil || *cfg.DNS.Strategy != "prefer_ipv4" {
					t.Errorf("DNS.Strategy = %v, want prefer_ipv4", cfg.DNS.Strategy)
				}
			},
		},
		{
			name: "jsonnet with import error",
			setup: func(t *testing.T, _, dir string) {
				t.Helper()
				mustWriteFile(t, filepath.Join(dir, ".cheburbox.jsonnet"), `
local x = import "nonexistent.jsonnet";
{version: 1, dns: x}
`)
			},
			wantErr: true,
		},
		{
			name: "jsonnet output is invalid config",
			setup: func(t *testing.T, _, dir string) {
				t.Helper()
				mustWriteFile(t, filepath.Join(dir, ".cheburbox.jsonnet"), `{not: "valid cheburbox config"}`)
			},
			wantErr: true,
		},
		{
			name: "jsonnet takes precedence over json",
			setup: func(t *testing.T, _, dir string) {
				t.Helper()
				mustWriteFile(t, filepath.Join(dir, ".cheburbox.jsonnet"), `
{version: 1, endpoint: "from-jsonnet", dns: {servers: [], final: ""}}
`)
				mustWriteFile(
					t,
					filepath.Join(dir, "cheburbox.json"),
					`{"version":1,"endpoint":"from-json","dns":{"servers":[],"final":""}}`,
				)
			},
			check: func(t *testing.T, cfg Config) {
				t.Helper()
				if cfg.Endpoint != "from-jsonnet" {
					t.Errorf("Endpoint = %q, want %q (jsonnet should take precedence)", cfg.Endpoint, "from-jsonnet")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			root := t.TempDir()
			dir := filepath.Join(root, "server-a")
			mustMkdirAll(t, dir)
			tt.setup(t, root, dir)

			cfg, err := LoadServerWithJsonnet(dir, root)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.check != nil {
				tt.check(t, cfg)
			}
		})
	}
}

func TestValidate(t *testing.T) {
	t.Parallel()

	//nolint:govet // fieldalignment: test table struct, readability over micro-optimization.
	tests := []struct {
		name    string
		errMsg  string
		config  Config
		wantErr bool
	}{
		{
			name: "valid minimal config",
			config: Config{
				Version: 1,
				DNS: DNS{
					Servers: []DNSServer{{Type: "local", Tag: "dns-local"}},
					Final:   strPtr("dns-local"),
				},
			},
		},
		{
			name: "valid config with inbounds and endpoint",
			config: Config{
				Version:  1,
				Endpoint: "1.2.3.4",
				DNS: DNS{
					Servers: []DNSServer{{Type: "local", Tag: "dns-local"}},
					Final:   strPtr("dns-local"),
				},
				Inbounds: []Inbound{
					{Tag: "vless-in", Type: "vless", ListenPort: 443},
				},
			},
		},
		{
			name: "error on unsupported version",
			config: Config{
				Version: 2,
				DNS: DNS{
					Servers: []DNSServer{{Type: "local", Tag: "dns-local"}},
				},
			},
			wantErr: true,
			errMsg:  "unsupported version",
		},
		{
			name:    "error on missing DNS section",
			config:  Config{Version: 1},
			wantErr: true,
			errMsg:  "dns section is required",
		},
		{
			name: "error on inbounds without endpoint",
			config: Config{
				Version: 1,
				DNS: DNS{
					Servers: []DNSServer{{Type: "local", Tag: "dns-local"}},
				},
				Inbounds: []Inbound{
					{Tag: "vless-in", Type: "vless", ListenPort: 443},
				},
			},
			wantErr: true,
			errMsg:  "endpoint is required",
		},
		{
			name: "outbounds only without endpoint is valid",
			config: Config{
				Version: 1,
				DNS: DNS{
					Servers: []DNSServer{{Type: "local", Tag: "dns-local"}},
				},
				Outbounds: []Outbound{
					{Type: "direct", Tag: "direct"},
				},
			},
		},
		{
			name: "error on negative listen_port",
			config: Config{
				Version:  1,
				Endpoint: "1.2.3.4",
				DNS: DNS{
					Servers: []DNSServer{{Type: "local", Tag: "dns-local"}},
					Final:   strPtr("dns-local"),
				},
				Inbounds: []Inbound{
					{Tag: "in1", Type: "vless", ListenPort: -1},
				},
			},
			wantErr: true,
			errMsg:  "listen_port",
		},
		{
			name: "error on listen_port above 65535",
			config: Config{
				Version:  1,
				Endpoint: "1.2.3.4",
				DNS: DNS{
					Servers: []DNSServer{{Type: "local", Tag: "dns-local"}},
					Final:   strPtr("dns-local"),
				},
				Inbounds: []Inbound{
					{Tag: "in1", Type: "vless", ListenPort: 70000},
				},
			},
			wantErr: true,
			errMsg:  "listen_port",
		},
		{
			name: "zero listen_port is valid",
			config: Config{
				Version:  1,
				Endpoint: "1.2.3.4",
				DNS: DNS{
					Servers: []DNSServer{{Type: "local", Tag: "dns-local"}},
					Final:   strPtr("dns-local"),
				},
				Inbounds: []Inbound{
					{Tag: "in1", Type: "tun", ListenPort: 0},
				},
			},
		},
		{
			name: "max valid listen_port 65535",
			config: Config{
				Version:  1,
				Endpoint: "1.2.3.4",
				DNS: DNS{
					Servers: []DNSServer{{Type: "local", Tag: "dns-local"}},
					Final:   strPtr("dns-local"),
				},
				Inbounds: []Inbound{
					{Tag: "in1", Type: "vless", ListenPort: 65535},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := Validate(tt.config)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if tt.errMsg != "" && !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("error = %q, want to contain %q", err.Error(), tt.errMsg)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestIntegrationRoundTrip(t *testing.T) {
	t.Parallel()

	root := t.TempDir()

	libDir := filepath.Join(root, "lib")
	mustMkdirAll(t, libDir)
	mustWriteFile(t, filepath.Join(libDir, "dns.jsonnet"), `
{
	servers: [
		{type: "local", tag: "dns-local"},
		{type: "tls", tag: "dns-remote", server: "8.8.8.8", server_port: 853, detour: "direct"},
	],
	final: "dns-remote",
	strategy: "prefer_ipv4",
}
`)

	mustMkdirAll(t, filepath.Join(root, "server-a"))
	mustWriteFile(t, filepath.Join(root, "server-a", ".cheburbox.jsonnet"), `
local dns = import "lib/dns.jsonnet";
{
	version: 1,
	endpoint: "138.124.181.194",
	dns: dns,
	inbounds: [
		{
			tag: "vless-in",
			type: "vless",
			listen_port: 443,
			users: [{"name": "desktop"}, {"name": "Laptop"}],
		},
		{
			tag: "hy2-in",
			type: "hysteria2",
			listen_port: 443,
			up_mbps: 1000,
			down_mbps: 1000,
		},
	],
	outbounds: [
		{type: "direct", tag: "direct"},
	],
}
`)

	mustMkdirAll(t, filepath.Join(root, "server-b"))
	mustWriteFile(t, filepath.Join(root, "server-b", "cheburbox.json"), `{
		"version": 1,
		"dns": {
			"servers": [
				{"type": "local", "tag": "dns-local", "default_resolver": true}
			],
			"final": "dns-local"
		},
		"outbounds": [
			{"type": "direct", "tag": "direct"},
			{
				"type": "vless",
				"tag": "server-a-vless",
				"server": "server-a",
				"inbound": "vless-in",
				"user": "server-b"
			}
		]
	}`)

	mustMkdirAll(t, filepath.Join(root, "not-a-server"))

	servers, err := Discover(root)
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	if len(servers) != 2 {
		t.Fatalf("discover found %d servers, want 2: %v", len(servers), servers)
	}

	jpathAbs := root
	cfgA, err := LoadServerWithJsonnet(filepath.Join(root, "server-a"), jpathAbs)
	if err != nil {
		t.Fatalf("load server-a: %v", err)
	}

	cfgB, err := LoadServerWithJsonnet(filepath.Join(root, "server-b"), jpathAbs)
	if err != nil {
		t.Fatalf("load server-b: %v", err)
	}

	if err := Validate(cfgA); err != nil {
		t.Fatalf("validate server-a: %v", err)
	}
	if err := Validate(cfgB); err != nil {
		t.Fatalf("validate server-b: %v", err)
	}

	if cfgA.Endpoint != "138.124.181.194" {
		t.Errorf("server-a endpoint = %q, want %q", cfgA.Endpoint, "138.124.181.194")
	}
	if len(cfgA.Inbounds) != 2 {
		t.Fatalf("server-a inbounds = %d, want 2", len(cfgA.Inbounds))
	}
	if cfgA.Inbounds[0].Type != "vless" {
		t.Errorf("server-a inbound[0] type = %q, want vless", cfgA.Inbounds[0].Type)
	}
	if len(cfgA.Inbounds[0].Users) != 2 {
		t.Errorf("server-a inbound[0] users = %d, want 2", len(cfgA.Inbounds[0].Users))
	}
	if len(cfgA.DNS.Servers) != 2 {
		t.Errorf("server-a dns servers = %d, want 2", len(cfgA.DNS.Servers))
	}
	if cfgA.DNS.Servers[0].Tag != "dns-local" {
		t.Errorf("server-a dns[0] tag = %q, want %q", cfgA.DNS.Servers[0].Tag, "dns-local")
	}

	if cfgB.Endpoint != "" {
		t.Errorf("server-b endpoint = %q, want empty (no inbounds)", cfgB.Endpoint)
	}
	if len(cfgB.Outbounds) != 2 {
		t.Fatalf("server-b outbounds = %d, want 2", len(cfgB.Outbounds))
	}
	if cfgB.Outbounds[1].Type != "vless" {
		t.Errorf("server-b outbound[1] type = %q, want vless", cfgB.Outbounds[1].Type)
	}
	if cfgB.Outbounds[1].Server != "server-a" {
		t.Errorf("server-b outbound[1] server = %q, want server-a", cfgB.Outbounds[1].Server)
	}
}
