package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGenerateRun(t *testing.T) {
	t.Parallel()

	tests := []struct {
		setup   func(t *testing.T, root string)
		name    string
		server  string
		wantOut []string
		wantErr bool
	}{
		{
			name: "generate all discovers and generates servers",
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
			server:  "",
			wantOut: []string{"Generated 1 files for server server-a", "Generated 1 files for server server-b"},
		},
		{
			name: "generate specific server",
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
			server:  "server-a",
			wantOut: []string{"Generated 1 files for server server-a"},
		},
		{
			name:    "generate nonexistent server returns error",
			setup:   func(t *testing.T, _ string) { t.Helper() },
			server:  "nonexistent",
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
			server:  "bad-server",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			root := t.TempDir()
			tt.setup(t, root)

			var buf bytes.Buffer
			err := runGenerate(&buf, root, "lib", tt.server, false, false)
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
		})
	}
}

func TestGenerateWritesConfig(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	setupServer(t, root, "my-server", `{
		"version": 1,
		"endpoint": "1.2.3.4",
		"dns": {
			"servers": [{"type": "local", "tag": "dns-local"}],
			"final": "dns-local"
		},
		"inbounds": [{"tag": "vless-in", "type": "vless", "listen_port": 443, "users": [{"name": "alice"}]}],
		"outbounds": [{"type": "direct", "tag": "direct"}]
	}`)

	var buf bytes.Buffer
	err := runGenerate(&buf, root, "lib", "my-server", false, false)
	if err != nil {
		t.Fatalf("runGenerate: %v", err)
	}

	configPath := filepath.Join(root, "my-server", "config.json")
	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read config.json: %v", err)
	}

	var parsed map[string]any
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("parse config.json: %v", err)
	}

	for _, section := range []string{"dns", "route", "inbounds", "outbounds"} {
		if parsed[section] == nil {
			t.Errorf("expected %q section in generated config.json", section)
		}
	}

	if !strings.Contains(buf.String(), "Generated 1 files for server my-server") {
		t.Errorf("expected summary output, got: %s", buf.String())
	}
}

func TestGenerateCredentialPersistence(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	setupServer(t, root, "srv", `{
		"version": 1,
		"endpoint": "1.2.3.4",
		"dns": {
			"servers": [{"type": "local", "tag": "dns-local"}],
			"final": "dns-local"
		},
		"inbounds": [{"tag": "vless-in", "type": "vless", "listen_port": 443, "users": [{"name": "alice"}]}],
		"outbounds": [{"type": "direct", "tag": "direct"}]
	}`)

	var buf1 bytes.Buffer
	err := runGenerate(&buf1, root, "lib", "srv", false, false)
	if err != nil {
		t.Fatalf("first runGenerate: %v", err)
	}

	configPath := filepath.Join(root, "srv", "config.json")
	data1, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read config.json after first run: %v", err)
	}

	var buf2 bytes.Buffer
	err = runGenerate(&buf2, root, "lib", "srv", false, false)
	if err != nil {
		t.Fatalf("second runGenerate: %v", err)
	}

	data2, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read config.json after second run: %v", err)
	}

	if string(data1) != string(data2) {
		t.Error("credentials not persisted: config.json differs between runs")
	}
}

func TestGenerateDryRun(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	setupServer(t, root, "srv-a", `{
		"version": 1,
		"endpoint": "1.2.3.4",
		"dns": {
			"servers": [{"type": "local", "tag": "dns-local"}],
			"final": "dns-local"
		},
		"outbounds": [{"type": "direct", "tag": "direct"}]
	}`)

	var buf bytes.Buffer
	err := runGenerate(&buf, root, "lib", "", false, true)
	if err != nil {
		t.Fatalf("runGenerate: %v", err)
	}

	var output []map[string]any
	if err := json.Unmarshal(buf.Bytes(), &output); err != nil {
		t.Fatalf("parse dry-run output: %v", err)
	}

	if len(output) != 1 {
		t.Fatalf("expected 1 server entry, got %d", len(output))
	}
	if output[0]["server"] != "srv-a" {
		t.Errorf("server = %v, want srv-a", output[0]["server"])
	}
	files, ok := output[0]["files"].([]any)
	if !ok || len(files) == 0 {
		t.Fatal("expected files array")
	}
}

func TestGenerateDryRunNoDiskWrite(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	setupServer(t, root, "srv-a", `{
		"version": 1,
		"endpoint": "1.2.3.4",
		"dns": {
			"servers": [{"type": "local", "tag": "dns-local"}],
			"final": "dns-local"
		},
		"outbounds": [{"type": "direct", "tag": "direct"}]
	}`)

	var buf bytes.Buffer
	err := runGenerate(&buf, root, "lib", "", false, true)
	if err != nil {
		t.Fatalf("runGenerate: %v", err)
	}

	configPath := filepath.Join(root, "srv-a", "config.json")
	if _, err := os.Stat(configPath); err == nil {
		t.Fatal("config.json should not be written in dry-run mode")
	}
}

func TestResolveJPath(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		root string
		path string
		want string
	}{
		{name: "empty returns empty", root: "/project", path: "", want: ""},
		{name: "absolute path passthrough", root: "/project", path: "/opt/lib", want: "/opt/lib"},
		{name: "relative path joined", root: "/project", path: "lib", want: "/project/lib"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := resolveJPath(tt.root, tt.path)
			if got != tt.want {
				t.Errorf("resolveJPath(%q, %q) = %q, want %q", tt.root, tt.path, got, tt.want)
			}
		})
	}
}

func TestRuleSetCompileCommand(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	ruleSetSource := `{"rules": [{"domain_suffix": [".example.com"]}]}`
	inputPath := filepath.Join(dir, "test.json")
	if err := os.WriteFile(inputPath, []byte(ruleSetSource), 0o644); err != nil {
		t.Fatalf("write source: %v", err)
	}

	outputPath := filepath.Join(dir, "test.srs")

	rootCmd := NewRootCommand()
	rootCmd.SetArgs([]string{"rule-set", "compile", "--input", inputPath, "--output", outputPath})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}

	if _, err := os.Stat(outputPath); err != nil {
		t.Fatalf("output file not created: %v", err)
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
