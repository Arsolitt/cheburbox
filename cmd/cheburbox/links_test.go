package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Arsolitt/cheburbox/generate"
)

// setupVLESSServer creates a server directory with a VLESS+Reality cheburbox.json
// and runs generate to produce config.json with real credentials.
func setupVLESSServer(t *testing.T, root string, name string) {
	t.Helper()

	setupServer(t, root, name, `{
		"version": 1,
		"endpoint": "1.2.3.4",
		"dns": {
			"servers": [{"type": "local", "tag": "dns-local"}],
			"final": "dns-local"
		},
		"inbounds": [{
			"tag": "vless-in",
			"type": "vless",
			"listen_port": 443,
			"tls": {
				"reality": {
					"handshake": {"server": "www.example.com", "server_port": 443}
				}
			},
			"users": [{"name": "alice", "flow": "xtls-rprx-vision"}]
		}],
		"outbounds": [{"type": "direct", "tag": "direct"}]
	}`)

	var buf bytes.Buffer
	if err := runGenerate(&buf, root, "lib", name, generate.GenerateConfig{}, false); err != nil {
		t.Fatalf("generate config for %s: %v", name, err)
	}
}

func TestRunLinks_URIFormat(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	setupVLESSServer(t, root, "srv1")

	var buf bytes.Buffer
	err := runLinks(&buf, root, "lib", "", "", "", "uri")
	if err != nil {
		t.Fatalf("runLinks: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "vless://") {
		t.Errorf("expected vless:// URI in output, got:\n%s", output)
	}
}

func TestRunLinks_JSONFormat(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	setupVLESSServer(t, root, "srv1")

	var buf bytes.Buffer
	err := runLinks(&buf, root, "lib", "", "", "", "json")
	if err != nil {
		t.Fatalf("runLinks: %v", err)
	}

	// JSON format produces pretty-printed objects; decode them from the stream.
	dec := json.NewDecoder(&buf)

	objectCount := 0

	for dec.More() {
		var parsed map[string]json.RawMessage
		if err := dec.Decode(&parsed); err != nil {
			t.Fatalf("decode JSON object: %v", err)
		}

		if _, ok := parsed["type"]; !ok {
			t.Errorf("JSON object missing 'type' field")
		}

		if _, ok := parsed["tag"]; !ok {
			t.Errorf("JSON object missing 'tag' field")
		}

		objectCount++
	}

	if objectCount == 0 {
		t.Fatal("expected at least one JSON object in output")
	}
}

func TestRunLinks_ServerFilter(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	setupVLESSServer(t, root, "srv-alpha")
	setupVLESSServer(t, root, "srv-beta")

	// Request only srv-alpha links.
	var buf bytes.Buffer
	err := runLinks(&buf, root, "lib", "srv-alpha", "", "", "uri")
	if err != nil {
		t.Fatalf("runLinks: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "vless://") {
		t.Errorf("expected vless:// URI for srv-alpha, got:\n%s", output)
	}

	// The fragment in a VLESS URI encodes server-tag-user; verify srv-beta is absent.
	if strings.Contains(output, "srv-beta") {
		t.Errorf("output should not contain srv-beta links, got:\n%s", output)
	}
}

func TestRunLinks_InvalidFormat(t *testing.T) {
	t.Parallel()

	root := t.TempDir()

	var buf bytes.Buffer
	err := runLinks(&buf, root, "lib", "", "", "", "xml")
	if err == nil {
		t.Fatal("expected error for invalid format, got nil")
	}

	if !strings.Contains(err.Error(), "invalid format") {
		t.Errorf("error should mention invalid format, got: %v", err)
	}
}

func TestRunLinks_EmptyProject(t *testing.T) {
	t.Parallel()

	root := t.TempDir()

	var buf bytes.Buffer
	err := runLinks(&buf, root, "lib", "", "", "", "uri")
	if err != nil {
		t.Fatalf("runLinks on empty project: %v", err)
	}

	output := strings.TrimSpace(buf.String())
	if output != "" {
		t.Errorf("expected empty output for project with no servers, got:\n%s", output)
	}
}
