package main

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
		setup     func(t *testing.T, root string)
		name      string
		server    string
		wantOut   []string
		wantLines []string
		wantErr   bool
	}{
		{
			name: "generate all discovers and validates servers",
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
			server:    "",
			wantOut:   []string{"server-a", "server-b"},
			wantLines: []string{"  Version:  1\n", "  Inbounds: 1\n", "  Outbounds: 1\n"},
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
			wantOut: []string{"server-a"},
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
			err := runGenerate(&buf, root, "lib", tt.server)
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
			for _, wantLine := range tt.wantLines {
				if !strings.Contains(output, wantLine) {
					t.Errorf("output missing line %q\nGot:\n%s", wantLine, output)
				}
			}
		})
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
