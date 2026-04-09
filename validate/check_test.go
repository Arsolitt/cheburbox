package validate

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Arsolitt/cheburbox/config"
	"github.com/Arsolitt/cheburbox/generate"
)

func TestCheckHysteria2ServerNameCollision(t *testing.T) {
	t.Parallel()

	cfg := config.Config{
		Inbounds: []config.Inbound{
			{Type: "hysteria2", Tag: "hy2-a", TLS: &config.InboundTLS{ServerName: "example.com"}},
			{Type: "hysteria2", Tag: "hy2-b", TLS: &config.InboundTLS{ServerName: "example.com"}},
		},
	}

	errs := checkHysteria2ServerNameCollision("srv1", cfg)
	if len(errs) != 1 {
		t.Fatalf("expected 1 error, got %d: %v", len(errs), errs)
	}

	if !strings.Contains(errs[0].Error(), "hy2-a") || !strings.Contains(errs[0].Error(), "hy2-b") {
		t.Errorf("error should mention both tags, got: %v", errs[0])
	}

	if !strings.Contains(errs[0].Error(), "example.com") {
		t.Errorf("error should mention server_name, got: %v", errs[0])
	}
}

func TestCheckHysteria2ServerNameCollisionNoConflict(t *testing.T) {
	t.Parallel()

	cfg := config.Config{
		Inbounds: []config.Inbound{
			{Type: "hysteria2", Tag: "hy2-a", TLS: &config.InboundTLS{ServerName: "alpha.com"}},
			{Type: "hysteria2", Tag: "hy2-b", TLS: &config.InboundTLS{ServerName: "beta.com"}},
		},
	}

	errs := checkHysteria2ServerNameCollision("srv1", cfg)
	if len(errs) != 0 {
		t.Fatalf("expected 0 errors, got %d: %v", len(errs), errs)
	}
}

func TestCheckHysteria2ServerNameCollisionNoTLS(t *testing.T) {
	t.Parallel()

	cfg := config.Config{
		Inbounds: []config.Inbound{
			{Type: "hysteria2", Tag: "hy2-a"},
			{Type: "hysteria2", Tag: "hy2-b"},
		},
	}

	errs := checkHysteria2ServerNameCollision("srv1", cfg)
	if len(errs) != 0 {
		t.Fatalf("expected 0 errors, got %d: %v", len(errs), errs)
	}
}

func TestCheckHysteria2ServerNameCollisionNonHysteria2(t *testing.T) {
	t.Parallel()

	cfg := config.Config{
		Inbounds: []config.Inbound{
			{Type: "vless", Tag: "vl-a", TLS: &config.InboundTLS{ServerName: "example.com"}},
		},
	}

	errs := checkHysteria2ServerNameCollision("srv1", cfg)
	if len(errs) != 0 {
		t.Fatalf("expected 0 errors, got %d: %v", len(errs), errs)
	}
}

func TestCheckHysteria2ServerNameCollisionThreeWay(t *testing.T) {
	t.Parallel()

	cfg := config.Config{
		Inbounds: []config.Inbound{
			{Type: "hysteria2", Tag: "hy2-a", TLS: &config.InboundTLS{ServerName: "shared.com"}},
			{Type: "hysteria2", Tag: "hy2-b", TLS: &config.InboundTLS{ServerName: "other.com"}},
			{Type: "hysteria2", Tag: "hy2-c", TLS: &config.InboundTLS{ServerName: "shared.com"}},
		},
	}

	errs := checkHysteria2ServerNameCollision("srv1", cfg)
	if len(errs) != 1 {
		t.Fatalf("expected 1 error, got %d: %v", len(errs), errs)
	}

	if !strings.Contains(errs[0].Error(), "hy2-a") || !strings.Contains(errs[0].Error(), "hy2-c") {
		t.Errorf("error should mention colliding tags, got: %v", errs[0])
	}
}

func TestCheckOutboundInboundRefs(t *testing.T) {
	t.Parallel()

	configs := map[string]config.Config{
		"server-a": {
			Inbounds: []config.Inbound{
				{Type: "hysteria2", Tag: "hy2-in"},
			},
			Outbounds: []config.Outbound{
				{Type: "hysteria2", Tag: "cross-out", Server: "server-b", Inbound: "hy2-in-b"},
			},
		},
		"server-b": {
			Inbounds: []config.Inbound{
				{Type: "hysteria2", Tag: "hy2-in-b"},
			},
		},
	}

	errs := checkOutboundInboundRefs(configs)
	if len(errs) != 0 {
		t.Fatalf("expected 0 errors, got %d: %v", len(errs), errs)
	}
}

func TestCheckOutboundInboundRefsMissing(t *testing.T) {
	t.Parallel()

	configs := map[string]config.Config{
		"server-a": {
			Outbounds: []config.Outbound{
				{Type: "hysteria2", Tag: "cross-out", Server: "server-b", Inbound: "nonexistent"},
			},
		},
		"server-b": {
			Inbounds: []config.Inbound{
				{Type: "hysteria2", Tag: "hy2-in-b"},
			},
		},
	}

	errs := checkOutboundInboundRefs(configs)
	if len(errs) != 1 {
		t.Fatalf("expected 1 error, got %d: %v", len(errs), errs)
	}

	if !strings.Contains(errs[0].Error(), "nonexistent") {
		t.Errorf("error should mention missing inbound tag, got: %v", errs[0])
	}
}

func TestCheckOutboundInboundRefsNoCrossServer(t *testing.T) {
	t.Parallel()

	configs := map[string]config.Config{
		"server-a": {
			Outbounds: []config.Outbound{
				{Type: "direct", Tag: "direct-out"},
			},
		},
	}

	errs := checkOutboundInboundRefs(configs)
	if len(errs) != 0 {
		t.Fatalf("expected 0 errors, got %d: %v", len(errs), errs)
	}
}

func TestCheckOutboundGroupRefsValid(t *testing.T) {
	t.Parallel()

	cfg := config.Config{
		Outbounds: []config.Outbound{
			{Type: "direct", Tag: "direct"},
			{Type: "urltest", Tag: "group-a", Outbounds: []string{"direct"}},
			{Type: "selector", Tag: "group-b", Outbounds: []string{"direct", "group-a"}},
		},
	}

	errs := checkOutboundGroupRefs("srv1", cfg)
	if len(errs) != 0 {
		t.Fatalf("expected 0 errors, got %d: %v", len(errs), errs)
	}
}

func TestCheckOutboundGroupRefsInvalid(t *testing.T) {
	t.Parallel()

	cfg := config.Config{
		Outbounds: []config.Outbound{
			{Type: "direct", Tag: "direct"},
			{Type: "urltest", Tag: "group-a", Outbounds: []string{"direct", "unknown-out"}},
		},
	}

	errs := checkOutboundGroupRefs("srv1", cfg)
	if len(errs) != 1 {
		t.Fatalf("expected 1 error, got %d: %v", len(errs), errs)
	}

	if !strings.Contains(errs[0].Error(), "unknown-out") {
		t.Errorf("error should mention unknown outbound tag, got: %v", errs[0])
	}
}

func TestCheckOutboundGroupRefsNonGroupOutbound(t *testing.T) {
	t.Parallel()

	cfg := config.Config{
		Outbounds: []config.Outbound{
			{Type: "direct", Tag: "direct"},
			{Type: "hysteria2", Tag: "hy2-out"},
		},
	}

	errs := checkOutboundGroupRefs("srv1", cfg)
	if len(errs) != 0 {
		t.Fatalf("expected 0 errors, got %d: %v", len(errs), errs)
	}
}

func TestCheckOutboundGroupRefsEmptyOutbounds(t *testing.T) {
	t.Parallel()

	cfg := config.Config{
		Outbounds: []config.Outbound{
			{Type: "urltest", Tag: "group-a", Outbounds: []string{}},
		},
	}

	errs := checkOutboundGroupRefs("srv1", cfg)
	if len(errs) != 0 {
		t.Fatalf("expected 0 errors, got %d: %v", len(errs), errs)
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

func TestSingBoxCheckValidConfig(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	cfg := config.Config{
		Version: 1,
		DNS: config.DNS{
			Final:   new("dns-local"),
			Servers: []config.DNSServer{{Type: "local", Tag: "dns-local"}},
		},
		Outbounds: []config.Outbound{
			{Type: "direct", Tag: "direct"},
		},
		Route: &config.Route{
			Final:               "direct",
			AutoDetectInterface: true,
		},
	}

	setupTestServer(t, root, "test-srv", cfg)

	result, err := generate.GenerateServer(filepath.Join(root, "test-srv"), cfg, generate.GenerateConfig{})
	if err != nil {
		t.Fatalf("GenerateServer: %v", err)
	}

	configFile := findGenerateFile(result.Files, "config.json")
	if configFile == nil {
		t.Fatal("config.json not found in generated files")
	}

	configPath := filepath.Join(root, "config.json")
	if err := os.WriteFile(configPath, configFile.Content, 0o644); err != nil {
		t.Fatalf("write config.json: %v", err)
	}

	if err := singBoxCheck(configPath); err != nil {
		t.Errorf("singBoxCheck returned unexpected error: %v", err)
	}
}

func TestSingBoxCheckInvalidConfig(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")

	invalidConfig := `{"inbounds": [{"type": "invalid_type", "tag": "bad"}]}`
	if err := os.WriteFile(configPath, []byte(invalidConfig), 0o644); err != nil {
		t.Fatalf("write config.json: %v", err)
	}

	err := singBoxCheck(configPath)
	if err == nil {
		t.Error("singBoxCheck should return error for invalid config")
	}
}

func TestSingBoxCheckMissingFile(t *testing.T) {
	t.Parallel()

	err := singBoxCheck("/nonexistent/path/config.json")
	if err == nil {
		t.Error("singBoxCheck should return error for missing file")
	}

	if !strings.Contains(err.Error(), "read config.json") {
		t.Errorf("error should contain 'read config.json', got: %v", err)
	}
}

func TestValidateAllPhase1Only(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	cfg := config.Config{
		Version: 1,
		DNS: config.DNS{
			Final:   new("dns-local"),
			Servers: []config.DNSServer{{Type: "local", Tag: "dns-local"}},
		},
		Outbounds: []config.Outbound{
			{Type: "direct", Tag: "direct"},
		},
		Route: &config.Route{
			Final:               "direct",
			AutoDetectInterface: true,
		},
	}

	setupTestServer(t, root, "srv1", cfg)

	results, err := ValidateAll(root, "")
	if err != nil {
		t.Fatalf("ValidateAll returned unexpected error: %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}

	if results[0].Server != "srv1" {
		t.Errorf("expected server %q, got %q", "srv1", results[0].Server)
	}

	if results[0].Failed() {
		t.Errorf("expected no errors, got: %v", results[0].Errors)
	}
}

func TestValidateAllPhase1Errors(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	cfg := config.Config{
		Version: 2,
	}

	setupTestServer(t, root, "bad-srv", cfg)

	results, err := ValidateAll(root, "")
	if err != nil {
		t.Fatalf("ValidateAll returned unexpected error: %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}

	if !results[0].Failed() {
		t.Error("expected errors for invalid config")
	}
}

func TestValidateAllWithCycle(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	cfgA := config.Config{
		Version: 1,
		DNS: config.DNS{
			Final:   new("dns-local"),
			Servers: []config.DNSServer{{Type: "local", Tag: "dns-local"}},
		},
		Outbounds: []config.Outbound{
			{Type: "direct", Tag: "direct"},
			{Type: "direct", Tag: "to-b", Server: "srv-b", Inbound: "in-b"},
		},
		Route: &config.Route{
			Final:               "direct",
			AutoDetectInterface: true,
		},
	}
	cfgB := config.Config{
		Version: 1,
		DNS: config.DNS{
			Final:   new("dns-local"),
			Servers: []config.DNSServer{{Type: "local", Tag: "dns-local"}},
		},
		Inbounds: []config.Inbound{
			{Type: "direct", Tag: "in-b"},
		},
		Outbounds: []config.Outbound{
			{Type: "direct", Tag: "direct"},
			{Type: "direct", Tag: "to-a", Server: "srv-a", Inbound: "in-a"},
		},
		Route: &config.Route{
			Final:               "direct",
			AutoDetectInterface: true,
		},
	}

	setupTestServer(t, root, "srv-a", cfgA)
	setupTestServer(t, root, "srv-b", cfgB)

	results, err := ValidateAll(root, "")
	if err != nil {
		t.Fatalf("ValidateAll returned unexpected error: %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}

	if results[0].Server != "(global)" {
		t.Errorf("expected server %q, got %q", "(global)", results[0].Server)
	}

	if !results[0].Failed() {
		t.Fatal("expected errors for cyclic dependency")
	}

	if !strings.Contains(results[0].Errors[0].Error(), "cycle") {
		t.Errorf("error should mention cycle, got: %v", results[0].Errors[0])
	}
}

func TestValidateAllEmptyProject(t *testing.T) {
	t.Parallel()

	root := t.TempDir()

	results, err := ValidateAll(root, "")
	if err != nil {
		t.Fatalf("ValidateAll returned unexpected error: %v", err)
	}

	if len(results) != 0 {
		t.Fatalf("expected 0 results, got %d", len(results))
	}
}

func TestValidateServersWithServerFlag(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	validCfg := config.Config{
		Version: 1,
		DNS: config.DNS{
			Final:   new("dns-local"),
			Servers: []config.DNSServer{{Type: "local", Tag: "dns-local"}},
		},
		Outbounds: []config.Outbound{
			{Type: "direct", Tag: "direct"},
		},
		Route: &config.Route{
			Final:               "direct",
			AutoDetectInterface: true,
		},
	}

	setupTestServer(t, root, "target", validCfg)
	setupTestServer(t, root, "other", validCfg)

	results, err := ValidateServers(root, "", "target")
	if err != nil {
		t.Fatalf("ValidateServers returned unexpected error: %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}

	if results[0].Server != "target" {
		t.Errorf("expected server %q, got %q", "target", results[0].Server)
	}

	if results[0].Failed() {
		t.Errorf("expected no errors, got: %v", results[0].Errors)
	}
}
