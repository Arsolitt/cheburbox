# Phase 1 — Foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the project skeleton, configuration loading, discovery, jsonnet evaluation, and a skeleton `generate` command that reads and validates cheburbox.json configs.

**Architecture:** Cheburbox discovers server directories under a project root, evaluates jsonnet if present, parses `cheburbox.json` into typed Go structs, validates required fields, and wires everything behind a cobra CLI. Phase 1 produces a working CLI that can discover servers, load their configs, and validate them — no sing-box generation yet.

**Tech Stack:** Go 1.26.1, `github.com/spf13/cobra` (CLI), `github.com/google/go-jsonnet` (jsonnet evaluation), Go stdlib (`encoding/json`, `os`, `path/filepath`).

---

## File Map

| File | Responsibility |
|------|---------------|
| `cmd/cheburbox/main.go` | CLI entry point, cobra root command, global flags |
| `internal/config/cheburbox.go` | All Go structs for cheburbox.json schema |
| `internal/config/load.go` | Discovery, jsonnet eval, JSON parsing, loading |
| `internal/config/load_test.go` | Tests for discovery, parsing, jsonnet eval, validation |
| `internal/config/cheburbox_test.go` | Tests for struct marshaling/unmarshaling |
| `internal/cmd/generate.go` | `generate` subcommand wiring |

---

## Task 1: Project Setup and Minimal CLI

**Files:**
- Create: `cmd/cheburbox/main.go`

### Step 1: Install dependencies

```bash
go get github.com/spf13/cobra@latest
go get github.com/google/go-jsonnet@latest
```

### Step 2: Create the CLI entry point

Create `cmd/cheburbox/main.go`:

```go
// Package main is the CLI entry point for cheburbox.
package main

import (
	"os"

	"github.com/spf13/cobra"
)

func main() {
	rootCmd := &cobra.Command{
		Use:           "cheburbox",
		Short:         "Manage sing-box configurations across multiple servers.",
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
```

### Step 3: Verify it builds and runs

```bash
go build -o build/cheburbox ./cmd/cheburbox/
./build/cheburbox --help
```

Expected output includes usage text with `cheburbox` command.

### Step 4: Run linter

```bash
golangci-lint run --fix
```

### Step 5: Commit

```bash
git add cmd/cheburbox/main.go go.mod go.sum
git commit -m "feat: scaffold project with cobra CLI entry point"
```

---

## Task 2: Cheburbox Go Structs

**Files:**
- Create: `internal/config/cheburbox.go`
- Create: `internal/config/cheburbox_test.go`

### Step 1: Write the failing test

Create `internal/config/cheburbox_test.go`:

```go
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
				{"type": "local", "tag": "dns-local", "default_resolver": true},
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
	if !cfg.DNS.Servers[0].DefaultResolver {
		t.Error("DNS.Servers[0].DefaultResolver = false, want true")
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
			Servers:  []DNSServer{{Type: "local", Tag: "dns-local", DefaultResolver: true}},
			Final:    strPtr("dns-local"),
			Strategy: strPtr("prefer_ipv4"),
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
}

func strPtr(s string) *string {
	return &s
}
```

### Step 2: Run test to verify it fails

```bash
go test -run TestConfigUnmarshal ./internal/config/
```

Expected: FAIL — types not defined.

### Step 3: Write the implementation

Create `internal/config/cheburbox.go`:

```go
// Package config defines cheburbox.json schema types and provides loading,
// discovery, and validation for server configurations.
package config

import "encoding/json"

// CurrentSchemaVersion is the only supported cheburbox.json schema version.
const CurrentSchemaVersion = 1

// Config is the top-level cheburbox.json configuration.
type Config struct {
	Version  int              `json:"version"`
	Endpoint string           `json:"endpoint,omitempty"`
	Log      json.RawMessage `json:"log,omitempty"`

	DNS      DNS       `json:"dns"`
	Inbounds []Inbound `json:"inbounds,omitempty"`

	Outbounds []Outbound `json:"outbounds,omitempty"`
	Route     Route      `json:"route,omitempty"`
}

// DNS holds the DNS configuration section.
type DNS struct {
	Servers  []DNSServer       `json:"servers"`
	Rules    json.RawMessage   `json:"rules,omitempty"`
	Final    *string           `json:"final,omitempty"`
	Strategy *string           `json:"strategy,omitempty"`
}

// DNSServer represents a single DNS server entry.
type DNSServer struct {
	Type            string `json:"type"`
	Tag             string `json:"tag"`
	Server          string `json:"server,omitempty"`
	ServerPort      int    `json:"server_port,omitempty"`
	Detour          string `json:"detour,omitempty"`
	DefaultResolver bool   `json:"default_resolver,omitempty"`
}

// Inbound represents a single inbound configuration.
// Use Type field to determine which fields are relevant.
type Inbound struct {
	Tag        string           `json:"tag"`
	Type       string           `json:"type"`
	ListenPort int              `json:"listen_port,omitempty"`

	// VLESS fields.
	TLS   *InboundTLS `json:"tls,omitempty"`
	Users []string    `json:"users,omitempty"`

	// Hysteria2 fields.
	UpMbps   int                  `json:"up_mbps,omitempty"`
	DownMbps int                  `json:"down_mbps,omitempty"`
	Obfs     *ObfsConfig          `json:"obfs,omitempty"`
	Masq     *MasqueradeConfig    `json:"masquerade,omitempty"`

	// TUN fields.
	InterfaceName          string   `json:"interface_name,omitempty"`
	Address                []string `json:"address,omitempty"`
	MTU                    int      `json:"mtu,omitempty"`
	AutoRoute              bool     `json:"auto_route,omitempty"`
	Stack                  string   `json:"stack,omitempty"`
	EndpointIndependentNAT bool     `json:"endpoint_independent_nat,omitempty"`
	ExcludeInterface       []string `json:"exclude_interface,omitempty"`
	RouteExcludeAddress    []string `json:"route_exclude_address,omitempty"`
}

// InboundTLS holds TLS configuration for an inbound.
type InboundTLS struct {
	ServerName string               `json:"server_name,omitempty"`
	Reality    *RealityConfig       `json:"reality,omitempty"`
}

// RealityConfig holds TLS reality configuration for VLESS inbounds.
type RealityConfig struct {
	Handshake *RealityHandshake `json:"handshake"`
	ShortID   []string          `json:"short_id,omitempty"`
}

// RealityHandshake holds the handshake server details for reality.
type RealityHandshake struct {
	Server    string `json:"server"`
	ServerPort int   `json:"server_port"`
}

// ObfsConfig holds obfuscation configuration for hysteria2.
type ObfsConfig struct {
	Type     string `json:"type"`
	Password string `json:"password,omitempty"`
}

// MasqueradeConfig holds masquerade configuration for hysteria2.
type MasqueradeConfig struct {
	Type       string `json:"type"`
	URL        string `json:"url,omitempty"`
	RewriteHost bool  `json:"rewrite_host,omitempty"`
}

// Outbound represents a single outbound configuration.
// Use Type field to determine which fields are relevant.
type Outbound struct {
	Type string `json:"type"`
	Tag  string `json:"tag"`

	// Direct outbound fields — none beyond Type/Tag.

	// VLESS / Hysteria2 outbound fields.
	Server  string `json:"server,omitempty"`
	Inbound string `json:"inbound,omitempty"`
	User    string `json:"user,omitempty"`
	Flow    string `json:"flow,omitempty"`

	// VLESS outbound override.
	Endpoint string `json:"endpoint,omitempty"`

	// URLTest / Selector fields.
	Outbounds []string `json:"outbounds,omitempty"`
	URL       string   `json:"url,omitempty"`
	Interval  string   `json:"interval,omitempty"`
}

// Route holds the routing configuration section.
type Route struct {
	Final              string           `json:"final,omitempty"`
	AutoDetectInterface bool            `json:"auto_detect_interface,omitempty"`
	RuleSets           json.RawMessage `json:"rule_sets,omitempty"`
	CustomRuleSets     []string        `json:"custom_rule_sets,omitempty"`
	Rules              json.RawMessage `json:"rules,omitempty"`
}
```

### Step 4: Run test to verify it passes

```bash
go test -run TestConfig ./internal/config/ -v
```

Expected: PASS

### Step 5: Run linter

```bash
golangci-lint run --fix ./internal/config/
```

### Step 6: Commit

```bash
git add internal/config/cheburbox.go internal/config/cheburbox_test.go
git commit -m "feat: add cheburbox.json Go structs with full schema types"
```

---

## Task 3: Server Discovery

**Files:**
- Create: `internal/config/load.go`
- Modify: `internal/config/load_test.go` (append discovery tests)

### Step 1: Write the failing test

Append to `internal/config/load_test.go`:

```go
import (
	"os"
	"path/filepath"
	"sort"
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
				mustMkdirAll(t, filepath.Join(root, "random-file.txt"))
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
			name: "empty project root returns empty list",
			setup: func(t *testing.T, root string) {
				t.Helper()
			},
			want: []string{},
		},
		{
			name: "nonexistent root returns error",
			setup: func(t *testing.T, root string) {
				t.Helper()
			},
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
```

### Step 2: Run test to verify it fails

```bash
go test -run TestDiscover ./internal/config/ -v
```

Expected: FAIL — `Discover` not defined.

### Step 3: Write the implementation

Create `internal/config/load.go`:

```go
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

// configJSON is the static config filename.
const configJSON = "cheburbox.json"

// configJsonnet is the jsonnet config filename.
const configJsonnet = ".cheburbox.jsonnet"

// Discover finds all direct child directories under projectRoot that
// contain cheburbox.json or .cheburbox.jsonnet. Returns sorted directory names.
func Discover(projectRoot string) ([]string, error) {
	entries, err := os.ReadDir(projectRoot)
	if err != nil {
		return nil, fmt.Errorf("read project root %s: %w", projectRoot, err)
	}

	var servers []string

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		dirPath := filepath.Join(projectRoot, entry.Name())
		if hasConfig(dirPath) {
			servers = append(servers, entry.Name())
		}
	}

	sort.Strings(servers)
	return servers, nil
}

func hasConfig(dir string) bool {
	_, errJSON := os.Stat(filepath.Join(dir, configJSON))
	_, errJsonnet := os.Stat(filepath.Join(dir, configJsonnet))
	return errJSON == nil || errJsonnet == nil
}
```

### Step 4: Run test to verify it passes

```bash
go test -run TestDiscover ./internal/config/ -v
```

Expected: PASS

### Step 5: Run linter

```bash
golangci-lint run --fix ./internal/config/
```

### Step 6: Commit

```bash
git add internal/config/load.go internal/config/load_test.go
git commit -m "feat: add server directory discovery"
```

---

## Task 4: JSON Parsing — LoadServer

**Files:**
- Modify: `internal/config/load.go`
- Modify: `internal/config/load_test.go` (append parsing tests)

### Step 1: Write the failing test

Append to `internal/config/load_test.go`:

```go
func TestLoadServer(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		setup   func(t *testing.T, dir string)
		wantErr bool
		check   func(t *testing.T, cfg Config)
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
			name: "error on missing cheburbox.json",
			setup: func(t *testing.T, dir string) {
				t.Helper()
			},
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
						"servers": [{"type": "local", "tag": "dns-local", "default_resolver": true}],
						"final": "dns-local"
					},
					"inbounds": [
						{"tag": "vless-in", "type": "vless", "listen_port": 443, "users": ["alice"]}
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

			cfg, err := LoadServer(dir)
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
```

### Step 2: Run test to verify it fails

```bash
go test -run TestLoadServer ./internal/config/ -v
```

Expected: FAIL — `LoadServer` not defined.

### Step 3: Write the implementation

Append to `internal/config/load.go`:

```go
import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

// LoadServer reads and parses the cheburbox.json from the given directory.
// This is the simple loader without jsonnet support.
// Returns an error if no config file is found or parsing fails.
func LoadServer(dir string) (Config, error) {
	jsonPath := filepath.Join(dir, configJSON)

	_, err := os.Stat(jsonPath)
	if err != nil {
		return Config{}, fmt.Errorf("no config file found in %s", dir)
	}

	return loadFromJSON(jsonPath)
}

func loadFromJSON(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read %s: %w", path, err)
	}

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return Config{}, fmt.Errorf("parse %s: %w", path, err)
	}

	if cfg.Version == 0 {
		return Config{}, fmt.Errorf("%s: missing or zero version field", path)
	}

	return cfg, nil
}
```

### Step 4: Run test to verify it passes

```bash
go test -run TestLoadServer ./internal/config/ -v
```

Expected: PASS

### Step 5: Run linter

```bash
golangci-lint run --fix ./internal/config/
```

### Step 6: Commit

```bash
git add internal/config/load.go internal/config/load_test.go
git commit -m "feat: add LoadServer for cheburbox.json parsing"
```

---

## Task 5: Jsonnet Evaluation

**Files:**
- Modify: `internal/config/load.go`
- Modify: `internal/config/load_test.go` (append jsonnet tests)

### Step 1: Write the failing test

Append to `internal/config/load_test.go`:

```go
func TestLoadServerJsonnet(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		setup   func(t *testing.T, root, dir string)
		wantErr bool
		check   func(t *testing.T, cfg Config)
	}{
		{
			name: "evaluates simple jsonnet",
			setup: func(t *testing.T, root, dir string) {
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
	servers: [{type: "local", tag: "dns-local", default_resolver: true}],
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
				if !cfg.DNS.Servers[0].DefaultResolver {
					t.Error("DNS.Servers[0].DefaultResolver = false, want true")
				}
				if cfg.DNS.Strategy == nil || *cfg.DNS.Strategy != "prefer_ipv4" {
					t.Errorf("DNS.Strategy = %v, want prefer_ipv4", cfg.DNS.Strategy)
				}
			},
		},
		{
			name: "jsonnet with import error",
			setup: func(t *testing.T, root, dir string) {
				t.Helper()
				mustWriteFile(t, filepath.Join(dir, ".cheburbox.jsonnet"), `
local x = import "nonexistent.jsonnet";
{version: 1, dns: {servers: []}}
`)
			},
			wantErr: true,
		},
		{
			name: "jsonnet output is invalid config",
			setup: func(t *testing.T, root, dir string) {
				t.Helper()
				mustWriteFile(t, filepath.Join(dir, ".cheburbox.jsonnet"), `{not: "valid cheburbox config"}`)
			},
			wantErr: true,
		},
		{
			name: "jsonnet takes precedence over json",
			setup: func(t *testing.T, root, dir string) {
				t.Helper()
				mustWriteFile(t, filepath.Join(dir, ".cheburbox.jsonnet"), `
{version: 1, endpoint: "from-jsonnet", dns: {servers: [], final: ""}}
`)
				mustWriteFile(t, filepath.Join(dir, "cheburbox.json"), `{"version":1,"endpoint":"from-json","dns":{"servers":[],"final":""}}`)
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

			cfg, err := LoadServerWithJsonnet(dir, filepath.Join(root, "lib"))
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
```

### Step 2: Run test to verify it fails

```bash
go test -run TestLoadServerJsonnet ./internal/config/ -v
```

Expected: FAIL — `LoadServerWithJsonnet` not defined.

### Step 3: Write the implementation

Append to `internal/config/load.go`:

```go
import (
	"github.com/google/go-jsonnet"
)

// createJsonnetVM creates a jsonnet VM with the given jpath (library search path).
// jpath can be empty, in which case no additional import directories are set.
func createJsonnetVM(jpath string) *jsonnet.VM {
	vm := jsonnet.MakeVM()
	if jpath != "" {
		vm.Importer(&jsonnet.FileImporter{
			JPaths: []string{jpath},
		})
	}
	return vm
}

// LoadServerWithJsonnet reads, evaluates (if .cheburbox.jsonnet), and parses
// the config from dir. If jpath is non-empty, it is used as the jsonnet library
// search path. .cheburbox.jsonnet takes precedence over cheburbox.json.
func LoadServerWithJsonnet(dir string, jpath string) (Config, error) {
	jsonnetPath := filepath.Join(dir, configJsonnet)
	jsonPath := filepath.Join(dir, configJSON)

	_, errJsonnet := os.Stat(jsonnetPath)
	_, errJSON := os.Stat(jsonPath)

	switch {
	case errJsonnet == nil:
		vm := createJsonnetVM(jpath)
		output, err := vm.EvaluateFile(jsonnetPath)
		if err != nil {
			return Config{}, fmt.Errorf("evaluate jsonnet %s: %w", jsonnetPath, err)
		}

		var cfg Config
		if err := json.Unmarshal([]byte(output), &cfg); err != nil {
			return Config{}, fmt.Errorf("parse jsonnet output from %s: %w", jsonnetPath, err)
		}

		if cfg.Version == 0 {
			return Config{}, fmt.Errorf("%s: missing or zero version field", jsonnetPath)
		}

		return cfg, nil
	case errJSON == nil:
		return loadFromJSON(jsonPath)
	default:
		return Config{}, fmt.Errorf("no config file found in %s", dir)
	}
}
```

### Step 4: Run test to verify it passes

```bash
go test -run TestLoadServerJsonnet ./internal/config/ -v
```

Expected: PASS

### Step 5: Run linter

```bash
golangci-lint run --fix ./internal/config/
```

### Step 6: Commit

```bash
git add internal/config/load.go internal/config/load_test.go
git commit -m "feat: add jsonnet evaluation with jpath support"
```

---

## Task 6: Validation

**Files:**
- Modify: `internal/config/load.go`
- Modify: `internal/config/load_test.go` (append validation tests)

### Step 1: Write the failing test

Append to `internal/config/load_test.go`:

```go
func TestValidate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		config  Config
		wantErr bool
		errMsg  string
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
			wantErr: false,
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
			wantErr: false,
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
			name: "error on missing DNS section",
			config: Config{
				Version: 1,
			},
			wantErr: true,
			errMsg:  "dns section is required",
		},
		{
			name: "error on multiple default resolvers",
			config: Config{
				Version: 1,
				DNS: DNS{
					Servers: []DNSServer{
						{Type: "local", Tag: "dns-local", DefaultResolver: true},
						{Type: "tls", Tag: "dns-remote", Server: "8.8.8.8", DefaultResolver: true},
					},
				},
			},
			wantErr: true,
			errMsg:  "at most one dns server",
		},
		{
			name: "one default resolver is valid",
			config: Config{
				Version: 1,
				DNS: DNS{
					Servers: []DNSServer{
						{Type: "local", Tag: "dns-local", DefaultResolver: true},
						{Type: "tls", Tag: "dns-remote", Server: "8.8.8.8"},
					},
				},
			},
			wantErr: false,
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
			wantErr: false,
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
				if tt.errMsg != "" && !containsString(err.Error(), tt.errMsg) {
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

func containsString(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > 0 && len(substr) > 0 && findSubstring(s, substr)))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
```

### Step 2: Run test to verify it fails

```bash
go test -run TestValidate ./internal/config/ -v
```

Expected: FAIL — `Validate` not defined.

### Step 3: Write the implementation

Append to `internal/config/load.go`:

```go
import (
	"fmt"
)

// Validate checks a Config for required fields and consistency rules.
func Validate(cfg Config) error {
	if cfg.Version != CurrentSchemaVersion {
		return fmt.Errorf("unsupported version %d (want %d)", cfg.Version, CurrentSchemaVersion)
	}

	if len(cfg.DNS.Servers) == 0 {
		return fmt.Errorf("dns section is required: at least one dns server must be defined")
	}

	defaultCount := 0
	for _, srv := range cfg.DNS.Servers {
		if srv.DefaultResolver {
			defaultCount++
		}
	}
	if defaultCount > 1 {
		return fmt.Errorf("at most one dns server may have default_resolver: true, found %d", defaultCount)
	}

	if len(cfg.Inbounds) > 0 && cfg.Endpoint == "" {
		return fmt.Errorf("endpoint is required when inbounds are defined")
	}

	return nil
}
```

### Step 4: Run test to verify it passes

```bash
go test -run TestValidate ./internal/config/ -v
```

Expected: PASS

### Step 5: Run linter

```bash
golangci-lint run --fix ./internal/config/
```

### Step 6: Commit

```bash
git add internal/config/load.go internal/config/load_test.go
git commit -m "feat: add config validation rules"
```

---

## Task 7: CLI — Global Flags and Generate Command

**Files:**
- Modify: `cmd/cheburbox/main.go`
- Create: `internal/cmd/generate.go`

### Step 1: Write the failing test

Create `internal/cmd/generate_test.go`:

```go
package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGenerateRun(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		setup    func(t *testing.T, root string)
		args     []string
		wantErr  bool
		wantOut  []string
		wantNoOut []string
	}{
		{
			name: "generate --all discovers and validates servers",
			setup: func(t *testing.T, root string) {
				t.Helper()
				setupServer(t, root, "server-a", `{
					"version": 1,
					"endpoint": "1.2.3.4",
					"dns": {
						"servers": [{"type": "local", "tag": "dns-local"}],
						"final": "dns-local"
					},
					"inbounds": [{"tag": "vless-in", "type": "vless", "listen_port": 443}]
				}`)
				setupServer(t, root, "server-b", `{
					"version": 1,
					"dns": {
						"servers": [{"type": "local", "tag": "dns-local"}],
						"final": "dns-local"
					},
					"outbounds": [{"type": "direct", "tag": "direct"}]
				}`)
			},
			args:    []string{"--all"},
			wantOut: []string{"server-a", "server-b"},
		},
		{
			name: "generate --server validates specific server",
			setup: func(t *testing.T, root string) {
				t.Helper()
				setupServer(t, root, "server-a", `{
					"version": 1,
					"endpoint": "1.2.3.4",
					"dns": {
						"servers": [{"type": "local", "tag": "dns-local"}],
						"final": "dns-local"
					}
				}`)
			},
			args:    []string{"--server", "server-a"},
			wantOut: []string{"server-a"},
		},
		{
			name: "generate --server nonexistent returns error",
			setup: func(t *testing.T, root string) {
				t.Helper()
			},
			args:    []string{"--server", "nonexistent"},
			wantErr: true,
		},
		{
			name: "generate with invalid config returns error",
			setup: func(t *testing.T, root string) {
				t.Helper()
				setupServer(t, root, "bad-server", `{
					"version": 99,
					"dns": {"servers": []}
				}`)
			},
			args:    []string{"--all"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			root := t.TempDir()
			tt.setup(t, root)

			var buf bytes.Buffer
			err := RunGenerate(&buf, root, "lib", tt.args)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			output := buf.String()
			for _, want := range tt.wantOut {
				if !strings.Contains(output, want) {
					t.Errorf("output missing %q\nGot:\n%s", want, output)
				}
			}
			for _, notWant := range tt.wantNoOut {
				if strings.Contains(output, notWant) {
					t.Errorf("output should not contain %q\nGot:\n%s", notWant, output)
				}
			}
		})
	}
}

func setupServer(t *testing.T, root string, name string, content string) {
	t.Helper()
	dir := filepath.Join(root, name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdirall %s: %v", dir, err)
	}
	if err := os.WriteFile(filepath.Join(dir, "cheburbox.json"), []byte(content), 0o644); err != nil {
		t.Fatalf("writefile: %v", err)
	}
}
```

### Step 2: Run test to verify it fails

```bash
go test -run TestGenerateRun ./internal/cmd/ -v
```

Expected: FAIL — package `cmd` not found.

### Step 3: Write the implementation

Create `internal/cmd/generate.go`:

```go
// Package cmd implements cheburbox CLI subcommands.
package cmd

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/Arsolitt/cheburbox/internal/config"
)

// RunGenerate executes the generate command logic.
// projectRoot is the project root directory.
// jpath is the jsonnet library path (may be empty).
// args are the command arguments (--server, --all, etc.).
// Output is written to w.
func RunGenerate(w io.Writer, projectRoot string, jpath string, args []string) error {
	serverName, all, err := parseGenerateArgs(args)
	if err != nil {
		return fmt.Errorf("parse args: %w", err)
	}

	if all {
		return runGenerateAll(w, projectRoot, jpath)
	}

	return runGenerateServer(w, projectRoot, jpath, serverName)
}

func parseGenerateArgs(args []string) (serverName string, all bool, err error) {
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--server":
			if i+1 >= len(args) {
				return "", false, fmt.Errorf("--server requires a value")
			}
			serverName = args[i+1]
			i++
		case "--all":
			all = true
		default:
			return "", false, fmt.Errorf("unknown argument: %s", args[i])
		}
	}

	if serverName == "" && !all {
		all = true
	}

	return serverName, all, nil
}

func runGenerateAll(w io.Writer, projectRoot string, jpath string) error {
	servers, err := config.Discover(projectRoot)
	if err != nil {
		return fmt.Errorf("discover servers: %w", err)
	}

	if len(servers) == 0 {
		fmt.Fprintln(w, "no servers found in project")
		return nil
	}

	for _, name := range servers {
		if err := loadAndPrint(w, projectRoot, jpath, name); err != nil {
			return fmt.Errorf("server %s: %w", name, err)
		}
	}

	return nil
}

func runGenerateServer(w io.Writer, projectRoot string, jpath string, serverName string) error {
	dir := filepath.Join(projectRoot, serverName)
	if _, err := os.Stat(dir); err != nil {
		return fmt.Errorf("server %s: %w", serverName, err)
	}

	return loadAndPrint(w, projectRoot, jpath, serverName)
}

func loadAndPrint(w io.Writer, projectRoot string, jpath string, name string) error {
	dir := filepath.Join(projectRoot, name)
	jpathAbs := resolveJPath(projectRoot, jpath)

	cfg, err := config.LoadServerWithJsonnet(dir, jpathAbs)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	if err := config.Validate(cfg); err != nil {
		return fmt.Errorf("validate: %w", err)
	}

	fmt.Fprintf(w, "Server: %s\n", name)
	fmt.Fprintf(w, "  Version:  %d\n", cfg.Version)
	fmt.Fprintf(w, "  Endpoint: %s\n", cfg.Endpoint)
	fmt.Fprintf(w, "  Inbounds: %d\n", len(cfg.Inbounds))
	fmt.Fprintf(w, "  Outbounds: %d\n", len(cfg.Outbounds))
	fmt.Fprintf(w, "  DNS servers: %d\n", len(cfg.DNS.Servers))

	return nil
}

// resolveJPath returns an absolute jpath. If jpath is relative, it is resolved
// relative to projectRoot. If jpath is empty, returns empty.
func resolveJPath(projectRoot string, jpath string) string {
	if jpath == "" {
		return ""
	}
	if filepath.IsAbs(jpath) {
		return jpath
	}
	return filepath.Join(projectRoot, jpath)
}
```

Now update `cmd/cheburbox/main.go` to wire the generate command with global flags:

```go
// Package main is the CLI entry point for cheburbox.
package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/Arsolitt/cheburbox/internal/cmd"
)

func main() {
	var projectRoot string
	var jpath string

	rootCmd := &cobra.Command{
		Use:           "cheburbox",
		Short:         "Manage sing-box configurations across multiple servers.",
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	rootCmd.PersistentFlags().StringVar(&projectRoot, "project", "", "project root directory (default: CWD)")
	rootCmd.PersistentFlags().StringVar(&jpath, "jpath", "lib", "jsonnet library path")

	generateCmd := &cobra.Command{
		Use:   "generate",
		Short: "Load and validate server configurations.",
		RunE: func(cmd *cobra.Command, args []string) error {
			proj := projectRoot
			if proj == "" {
				var err error
				proj, err = os.Getwd()
				if err != nil {
					return fmt.Errorf("get working directory: %w", err)
				}
			}
			return cmd.RunGenerate(cmd.OutOrStdout(), proj, jpath, args)
		},
	}

	rootCmd.AddCommand(generateCmd)

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
```

Wait — there's a name collision. `cmd` is both the package variable and the import. Let me fix this:

```go
// Package main is the CLI entry point for cheburbox.
package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	cheburcmd "github.com/Arsolitt/cheburbox/internal/cmd"
)

func main() {
	var projectRoot string
	var jpath string

	rootCmd := &cobra.Command{
		Use:           "cheburbox",
		Short:         "Manage sing-box configurations across multiple servers.",
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	rootCmd.PersistentFlags().StringVar(&projectRoot, "project", "", "project root directory (default: CWD)")
	rootCmd.PersistentFlags().StringVar(&jpath, "jpath", "lib", "jsonnet library path")

	generateCmd := &cobra.Command{
		Use:   "generate",
		Short: "Load and validate server configurations.",
		RunE: func(command *cobra.Command, args []string) error {
			proj := projectRoot
			if proj == "" {
				var err error
				proj, err = os.Getwd()
				if err != nil {
					return fmt.Errorf("get working directory: %w", err)
				}
			}
			return cheburcmd.RunGenerate(command.OutOrStdout(), proj, jpath, args)
		},
	}

	rootCmd.AddCommand(generateCmd)

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
```

### Step 4: Run test to verify it passes

```bash
go test -run TestGenerateRun ./internal/cmd/ -v
```

Expected: PASS

### Step 5: Build and run manually

```bash
go build -o build/cheburbox ./cmd/cheburbox/
./build/cheburbox --help
./build/cheburbox generate --help
```

### Step 6: Run linter

```bash
golangci-lint run --fix
```

### Step 7: Commit

```bash
git add cmd/cheburbox/main.go internal/cmd/generate.go internal/cmd/generate_test.go
git commit -m "feat: add generate command with global flags"
```

---

## Task 8: Integration Test — Full Round-Trip

**Files:**
- Modify: `internal/config/load_test.go` (append integration tests)

### Step 1: Write the failing test

Append to `internal/config/load_test.go`:

```go
func TestIntegrationRoundTrip(t *testing.T) {
	t.Parallel()

	root := t.TempDir()

	// Create lib directory with shared jsonnet snippets.
	libDir := filepath.Join(root, "lib")
	mustMkdirAll(t, libDir)
	mustWriteFile(t, filepath.Join(libDir, "dns.jsonnet"), `
{
	servers: [
		{type: "local", tag: "dns-local", default_resolver: true},
		{type: "tls", tag: "dns-remote", server: "8.8.8.8", server_port: 853, detour: "direct"},
	],
	final: "dns-remote",
	strategy: "prefer_ipv4",
}
`)

	// Server A: uses jsonnet, has inbounds (needs endpoint).
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
			users: ["desktop", "Laptop"],
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

	// Server B: uses plain JSON, no inbounds (client).
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

	// Empty directory should be ignored.
	mustMkdirAll(t, filepath.Join(root, "not-a-server"))

	// Step 1: Discover.
	servers, err := Discover(root)
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	if len(servers) != 2 {
		t.Fatalf("discover found %d servers, want 2: %v", len(servers), servers)
	}

	// Step 2: Load each server with jsonnet support.
	jpathAbs := libDir
	cfgA, err := LoadServerWithJsonnet(filepath.Join(root, "server-a"), jpathAbs)
	if err != nil {
		t.Fatalf("load server-a: %v", err)
	}

	cfgB, err := LoadServerWithJsonnet(filepath.Join(root, "server-b"), jpathAbs)
	if err != nil {
		t.Fatalf("load server-b: %v", err)
	}

	// Step 3: Validate each server.
	if err := Validate(cfgA); err != nil {
		t.Fatalf("validate server-a: %v", err)
	}
	if err := Validate(cfgB); err != nil {
		t.Fatalf("validate server-b: %v", err)
	}

	// Step 4: Verify server-a config details.
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
	if !cfgA.DNS.Servers[0].DefaultResolver {
		t.Error("server-a dns[0] should be default resolver")
	}

	// Step 5: Verify server-b config details.
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
```

### Step 2: Run test to verify it passes

```bash
go test -run TestIntegrationRoundTrip ./internal/config/ -v
```

Expected: PASS

### Step 3: Run all tests

```bash
go test ./... -v
```

Expected: ALL PASS

### Step 4: Run linter

```bash
golangci-lint run --fix
```

### Step 5: Commit

```bash
git add internal/config/load_test.go
git commit -m "test: add integration test for full discovery-load-validate round-trip"
```

---

## Final Verification

After all tasks are complete, run the full suite:

```bash
go build -o build/cheburbox ./cmd/cheburbox/
go test ./... -cover
golangci-lint run
```

All should pass with no errors.

---

## Self-Review Checklist

- [x] Spec coverage: all Phase 1 items from the design doc are covered (CLI setup, structs, discovery, jsonnet, parsing, validation, generate command)
- [x] No placeholders: every step has complete code, commands, and expected output
- [x] TDD pattern: every task follows write failing test → verify fail → implement → verify pass → commit
- [x] Code style: follows AGENTS.md (120 char lines, import grouping, no naked/named returns, error wrapping, doc comments, log/slog, t.TempDir())
- [x] No `utils` or `common` package names
- [x] File paths are exact and complete
- [x] All struct types from the design doc schema are represented
- [x] `json.RawMessage` used for Log, DNS rules, route rule_sets, route rules (not validated in Phase 1)
- [x] Validation covers all Phase 1 rules (version==1, DNS present, at most one default_resolver, endpoint for inbounds)
- [x] `.cheburbox.jsonnet` takes precedence over `cheburbox.json`
- [x] Discovery is one level deep only
- [x] `--project` and `--jpath` global flags implemented
- [x] `generate --all` and `generate --server <name>` flags implemented
- [x] No sing-box dependency (deferred to Phase 2)
