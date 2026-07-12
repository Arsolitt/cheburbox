package validate

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Arsolitt/amnezigo"

	"github.com/Arsolitt/cheburbox/config"
	"github.com/Arsolitt/cheburbox/generate"
)

func TestCheckHysteria2ServerNameCollision(t *testing.T) {
	t.Parallel()

	cfg := config.Config{
		Inbounds: []config.Inbound{
			{Type: generate.TypeHysteria2, Tag: "hy2-a", TLS: &config.InboundTLS{ServerName: "example.com"}},
			{Type: generate.TypeHysteria2, Tag: "hy2-b", TLS: &config.InboundTLS{ServerName: "example.com"}},
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
			{Type: generate.TypeHysteria2, Tag: "hy2-a", TLS: &config.InboundTLS{ServerName: "alpha.com"}},
			{Type: generate.TypeHysteria2, Tag: "hy2-b", TLS: &config.InboundTLS{ServerName: "beta.com"}},
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
			{Type: generate.TypeHysteria2, Tag: "hy2-a"},
			{Type: generate.TypeHysteria2, Tag: "hy2-b"},
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
			{Type: generate.TypeHysteria2, Tag: "hy2-a", TLS: &config.InboundTLS{ServerName: "shared.com"}},
			{Type: generate.TypeHysteria2, Tag: "hy2-b", TLS: &config.InboundTLS{ServerName: "other.com"}},
			{Type: generate.TypeHysteria2, Tag: "hy2-c", TLS: &config.InboundTLS{ServerName: "shared.com"}},
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
				{Type: generate.TypeHysteria2, Tag: "hy2-in"},
			},
			Outbounds: []config.Outbound{
				{Type: generate.TypeHysteria2, Tag: "cross-out", Server: "server-b", Inbound: "hy2-in-b"},
			},
		},
		"server-b": {
			Inbounds: []config.Inbound{
				{Type: generate.TypeHysteria2, Tag: "hy2-in-b"},
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
				{Type: generate.TypeHysteria2, Tag: "cross-out", Server: "server-b", Inbound: "nonexistent"},
			},
		},
		"server-b": {
			Inbounds: []config.Inbound{
				{Type: generate.TypeHysteria2, Tag: "hy2-in-b"},
			},
		},
	}

	errs := checkOutboundInboundRefs(configs)
	serverErrs := errs["server-a"]
	if len(serverErrs) != 1 {
		t.Fatalf("expected 1 error for server-a, got %d: %v", len(serverErrs), serverErrs)
	}

	if !strings.Contains(serverErrs[0].Error(), "nonexistent") {
		t.Errorf("error should mention missing inbound tag, got: %v", serverErrs[0])
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

func TestAmneziaWGAllowedIPsCollision(t *testing.T) {
	t.Parallel()

	const sharedAddr = "10.7.0.2/32"

	configs := map[string]config.Config{
		"awg-server": {
			Inbounds: []config.Inbound{
				{Type: generate.TypeAmneziaWG, Tag: "awg-in", ListenPort: 51820, Address: []string{"10.7.0.1/24"}},
			},
		},
		"client-a": {
			Outbounds: []config.Outbound{
				{
					Type:    generate.TypeAmneziaWG,
					Tag:     "awg-out",
					Server:  "awg-server",
					Inbound: "awg-in",
					Address: []string{sharedAddr},
				},
			},
		},
		"client-b": {
			Outbounds: []config.Outbound{
				{
					Type:    generate.TypeAmneziaWG,
					Tag:     "awg-out",
					Server:  "awg-server",
					Inbound: "awg-in",
					Address: []string{sharedAddr},
				},
			},
		},
	}

	errs := checkAmneziaWGAllowedIPsCollision(configs)

	for _, src := range []string{"client-a", "client-b"} {
		serverErrs := errs[src]
		if len(serverErrs) != 1 {
			t.Fatalf("server %q: expected 1 collision error, got %d: %v", src, len(serverErrs), serverErrs)
		}
		msg := serverErrs[0].Error()
		if !strings.Contains(msg, sharedAddr) {
			t.Errorf("server %q: error should mention address %q, got: %s", src, sharedAddr, msg)
		}
		if !strings.Contains(msg, "client-a") || !strings.Contains(msg, "client-b") {
			t.Errorf("server %q: error should name both clients, got: %s", src, msg)
		}
	}
}

func TestAmneziaWGAllowedIPsCollisionDistinct(t *testing.T) {
	t.Parallel()

	configs := map[string]config.Config{
		"awg-server": {
			Inbounds: []config.Inbound{
				{Type: generate.TypeAmneziaWG, Tag: "awg-in", ListenPort: 51820, Address: []string{"10.7.0.1/24"}},
			},
		},
		"client-a": {
			Outbounds: []config.Outbound{
				{
					Type:    generate.TypeAmneziaWG,
					Tag:     "awg-out",
					Server:  "awg-server",
					Inbound: "awg-in",
					Address: []string{"10.7.0.2/32"},
				},
			},
		},
		"client-b": {
			Outbounds: []config.Outbound{
				{
					Type:    generate.TypeAmneziaWG,
					Tag:     "awg-out",
					Server:  "awg-server",
					Inbound: "awg-in",
					Address: []string{"10.7.0.3/32"},
				},
			},
		},
	}

	errs := checkAmneziaWGAllowedIPsCollision(configs)
	if len(errs) != 0 {
		t.Fatalf("expected 0 collision errors for distinct addresses, got %d: %v", len(errs), errs)
	}
}

func TestCheckOutboundGroupRefsValid(t *testing.T) {
	t.Parallel()

	cfg := config.Config{
		Outbounds: []config.Outbound{
			{Type: "direct", Tag: "direct"},
			{Type: generate.TypeURLTest, Tag: "group-a", Outbounds: []string{"direct"}},
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
			{Type: generate.TypeURLTest, Tag: "group-a", Outbounds: []string{"direct", "unknown-out"}},
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
			{Type: generate.TypeHysteria2, Tag: "hy2-out"},
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
			{Type: generate.TypeURLTest, Tag: "group-a", Outbounds: []string{}},
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

	if results[0].Server != serverGlobal {
		t.Errorf("expected server %q, got %q", serverGlobal, results[0].Server)
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

func TestValidateAllWithGeneratedConfigs(t *testing.T) {
	projectRoot := t.TempDir()

	exitCfg := config.Config{
		Version:  1,
		Endpoint: "10.0.0.1",
		DNS: config.DNS{
			Final:   new("dns-local"),
			Servers: []config.DNSServer{{Type: "local", Tag: "dns-local"}},
		},
		Inbounds: []config.Inbound{
			{
				Tag:        "vless-in",
				Type:       "vless",
				ListenPort: 443,
				Users:      []config.InboundUser{{Name: "proxy-server"}},
			},
		},
		Outbounds: []config.Outbound{
			{Type: "direct", Tag: "direct"},
		},
		Route: &config.Route{
			Final:               "direct",
			AutoDetectInterface: true,
		},
	}

	proxyCfg := config.Config{
		Version: 1,
		DNS: config.DNS{
			Final:   new("dns-local"),
			Servers: []config.DNSServer{{Type: "local", Tag: "dns-local"}},
		},
		Outbounds: []config.Outbound{
			{Type: "direct", Tag: "direct"},
			{
				Type:    "vless",
				Tag:     "exit-vless",
				Server:  "exit-server",
				Inbound: "vless-in",
				User:    "proxy-server",
			},
		},
		Route: &config.Route{
			Final:               "direct",
			AutoDetectInterface: true,
		},
	}

	setupTestServer(t, projectRoot, "exit-server", exitCfg)
	setupTestServer(t, projectRoot, "proxy-server", proxyCfg)

	genResults, err := generate.GenerateAll(projectRoot, "", generate.GenerateConfig{})
	if err != nil {
		t.Fatalf("GenerateAll: %v", err)
	}

	for _, r := range genResults {
		dir := filepath.Join(projectRoot, r.Server)
		for _, f := range r.Files {
			path := filepath.Join(dir, f.Path)
			if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
				t.Fatalf("mkdir: %v", err)
			}
			if err := os.WriteFile(path, f.Content, 0o644); err != nil {
				t.Fatalf("write: %v", err)
			}
		}
	}

	validateResults, err := ValidateAll(projectRoot, "")
	if err != nil {
		t.Fatalf("ValidateAll: %v", err)
	}

	if len(validateResults) != 2 {
		t.Fatalf("expected 2 results, got %d", len(validateResults))
	}

	for _, r := range validateResults {
		if r.Failed() {
			for _, e := range r.Errors {
				t.Errorf("server %s failed: %v", r.Server, e)
			}
		}
	}
}

func TestValidateAllPhase2SkippedWithoutConfig(t *testing.T) {
	t.Parallel()

	projectRoot := t.TempDir()

	setupTestServer(t, projectRoot, "srv-a", config.Config{
		Version:  1,
		Endpoint: "1.2.3.4",
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
	})

	results, err := ValidateAll(projectRoot, "")
	if err != nil {
		t.Fatalf("ValidateAll: %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}

	if results[0].Failed() {
		t.Errorf("expected server to pass Phase 1, got errors: %v", results[0].Errors)
	}

	if len(results[0].Warnings) != 1 {
		t.Errorf(
			"expected 1 warning (skipped sing-box check), got %d: %v",
			len(results[0].Warnings),
			results[0].Warnings,
		)
	}
}

func TestCheckAmneziaWGInboundValid(t *testing.T) {
	t.Parallel()

	cfg := config.Config{
		Inbounds: []config.Inbound{
			{
				Type:       generate.TypeAmneziaWG,
				Tag:        "awg-in",
				ListenPort: 51820,
				Address:    []string{"10.0.0.1/24"},
				Amnezia:    &config.AmneziaConfig{Protocol: "quic"},
			},
		},
	}

	if errs := checkAmneziaWGInbounds("srv1", cfg); len(errs) != 0 {
		t.Fatalf("expected 0 errors, got %d: %v", len(errs), errs)
	}
}

func TestCheckAmneziaWGInboundMissingListenPort(t *testing.T) {
	t.Parallel()

	cfg := config.Config{
		Inbounds: []config.Inbound{
			{
				Type:    generate.TypeAmneziaWG,
				Tag:     "awg-in",
				Address: []string{"10.0.0.1/24"},
			},
		},
	}

	errs := checkAmneziaWGInbounds("srv1", cfg)
	if len(errs) != 1 {
		t.Fatalf("expected 1 error, got %d: %v", len(errs), errs)
	}

	if !strings.Contains(errs[0].Error(), "listen_port") {
		t.Errorf("error should mention listen_port, got: %v", errs[0])
	}
}

func TestCheckAmneziaWGInboundBadCIDR(t *testing.T) {
	t.Parallel()

	cfg := config.Config{
		Inbounds: []config.Inbound{
			{
				Type:       generate.TypeAmneziaWG,
				Tag:        "awg-in",
				ListenPort: 51820,
				Address:    []string{"not-a-cidr"},
			},
		},
	}

	errs := checkAmneziaWGInbounds("srv1", cfg)
	if len(errs) != 1 {
		t.Fatalf("expected 1 error, got %d: %v", len(errs), errs)
	}

	if !strings.Contains(errs[0].Error(), "address CIDR") {
		t.Errorf("error should mention address CIDR, got: %v", errs[0])
	}
}

func TestCheckAmneziaWGInboundInvalidProtocol(t *testing.T) {
	t.Parallel()

	cfg := config.Config{
		Inbounds: []config.Inbound{
			{
				Type:       generate.TypeAmneziaWG,
				Tag:        "awg-in",
				ListenPort: 51820,
				Address:    []string{"10.0.0.1/24"},
				Amnezia:    &config.AmneziaConfig{Protocol: "bogus"},
			},
		},
	}

	errs := checkAmneziaWGInbounds("srv1", cfg)
	if len(errs) != 1 {
		t.Fatalf("expected 1 error, got %d: %v", len(errs), errs)
	}

	if !strings.Contains(errs[0].Error(), "bogus") {
		t.Errorf("error should mention invalid protocol, got: %v", errs[0])
	}
}

// TestCheckAmneziaWGInboundValidProtocols asserts every accepted transport
// protocol produces zero errors. The list mirrors allowedAmneziaWGProtocols;
// amnezigo's protocol constants are unexported, so the list is literal here too.
func TestCheckAmneziaWGInboundValidProtocols(t *testing.T) {
	t.Parallel()

	validProtocols := []string{"quic", "dns", "dtls", "stun", "sip", "rtp", "random"}

	for _, proto := range validProtocols {
		t.Run(proto, func(t *testing.T) {
			t.Parallel()

			cfg := config.Config{
				Inbounds: []config.Inbound{
					{
						Type:       generate.TypeAmneziaWG,
						Tag:        "awg-in",
						ListenPort: 51820,
						Address:    []string{"10.0.0.1/24"},
						Amnezia:    &config.AmneziaConfig{Protocol: proto},
					},
				},
			}

			if errs := checkAmneziaWGInbounds("srv1", cfg); len(errs) != 0 {
				t.Fatalf("expected 0 errors, got %d: %v", len(errs), errs)
			}
		})
	}
}

// TestCheckAmneziaWGInboundValidPresets asserts every preset shipped by
// amnezigo is accepted. The list is read dynamically from ListPresets so the
// test stays in sync after future amnezigo bumps.
func TestCheckAmneziaWGInboundValidPresets(t *testing.T) {
	t.Parallel()

	for _, p := range amnezigo.ListPresets() {
		t.Run(p.Name, func(t *testing.T) {
			t.Parallel()

			cfg := config.Config{
				Inbounds: []config.Inbound{
					{
						Type:       generate.TypeAmneziaWG,
						Tag:        "awg-in",
						ListenPort: 51820,
						Address:    []string{"10.0.0.1/24"},
						Amnezia:    &config.AmneziaConfig{Preset: p.Name},
					},
				},
			}

			if errs := checkAmneziaWGInbounds("srv1", cfg); len(errs) != 0 {
				t.Fatalf("expected 0 errors, got %d: %v", len(errs), errs)
			}
		})
	}
}

// TestCheckAmneziaWGInboundUnknownPreset asserts an unrecognised preset name
// produces exactly one error that mentions "unknown amnezia preset".
func TestCheckAmneziaWGInboundUnknownPreset(t *testing.T) {
	t.Parallel()

	cfg := config.Config{
		Inbounds: []config.Inbound{
			{
				Type:       generate.TypeAmneziaWG,
				Tag:        "awg-in",
				ListenPort: 51820,
				Address:    []string{"10.0.0.1/24"},
				Amnezia:    &config.AmneziaConfig{Preset: "no-such-preset"},
			},
		},
	}

	errs := checkAmneziaWGInbounds("srv1", cfg)
	if len(errs) != 1 {
		t.Fatalf("expected 1 error, got %d: %v", len(errs), errs)
	}

	if !strings.Contains(errs[0].Error(), "unknown amnezia preset") {
		t.Errorf("error should mention unknown amnezia preset, got: %v", errs[0])
	}
}

func TestCheckAmneziaWGOutboundValid(t *testing.T) {
	t.Parallel()

	cfg := config.Config{
		Outbounds: []config.Outbound{
			{
				Type:    generate.TypeAmneziaWG,
				Tag:     "awg-out",
				Server:  "exit-server",
				Inbound: "awg-in",
				Address: []string{"10.0.0.5/32"},
			},
		},
	}

	if errs := checkAmneziaWGOutbounds("srv1", cfg); len(errs) != 0 {
		t.Fatalf("expected 0 errors, got %d: %v", len(errs), errs)
	}
}

func TestCheckAmneziaWGOutboundMissingServer(t *testing.T) {
	t.Parallel()

	cfg := config.Config{
		Outbounds: []config.Outbound{
			{
				Type:    generate.TypeAmneziaWG,
				Tag:     "awg-out",
				Inbound: "awg-in",
				Address: []string{"10.0.0.5/32"},
			},
		},
	}

	errs := checkAmneziaWGOutbounds("srv1", cfg)
	if len(errs) != 1 {
		t.Fatalf("expected 1 error, got %d: %v", len(errs), errs)
	}

	if !strings.Contains(errs[0].Error(), "target server") {
		t.Errorf("error should mention target server, got: %v", errs[0])
	}
}

func TestCheckOutboundGroupRefsFallbackValid(t *testing.T) {
	t.Parallel()

	cfg := config.Config{
		Outbounds: []config.Outbound{
			{Type: "direct", Tag: "direct"},
			{Type: generate.TypeFallback, Tag: "fb-group", Outbounds: []string{"direct"}},
		},
	}

	errs := checkOutboundGroupRefs("srv1", cfg)
	if len(errs) != 0 {
		t.Fatalf("expected 0 errors, got %d: %v", len(errs), errs)
	}
}

func TestCheckOutboundGroupRefsFallbackInvalid(t *testing.T) {
	t.Parallel()

	cfg := config.Config{
		Outbounds: []config.Outbound{
			{Type: "direct", Tag: "direct"},
			{Type: generate.TypeFallback, Tag: "fb-group", Outbounds: []string{"unknown-out"}},
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

func TestCheckOutboundGroupRefsFailoverValid(t *testing.T) {
	t.Parallel()

	cfg := config.Config{
		Outbounds: []config.Outbound{
			{Type: "direct", Tag: "direct"},
			{Type: generate.TypeFailover, Tag: "fo-group", Outbounds: []string{"direct"}},
		},
	}

	errs := checkOutboundGroupRefs("srv1", cfg)
	if len(errs) != 0 {
		t.Fatalf("expected 0 errors, got %d: %v", len(errs), errs)
	}
}

func TestCheckOutboundGroupRefsFailoverInvalid(t *testing.T) {
	t.Parallel()

	cfg := config.Config{
		Outbounds: []config.Outbound{
			{Type: "direct", Tag: "direct"},
			{Type: generate.TypeFailover, Tag: "fo-group", Outbounds: []string{"unknown-out"}},
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

func TestCheckFailoverStrategy(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		strategy  string
		wantError bool
	}{
		{name: "empty defaults to sequential", strategy: "", wantError: false},
		{name: "sequential", strategy: generate.FailoverStrategySequential, wantError: false},
		{name: "cycle", strategy: generate.FailoverStrategyCycle, wantError: false},
		{name: "invalid", strategy: "invalid", wantError: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cfg := config.Config{
				Outbounds: []config.Outbound{
					{Type: "direct", Tag: "direct"},
					{
						Type:      generate.TypeFailover,
						Tag:       "fo-group",
						Strategy:  tt.strategy,
						Outbounds: []string{"direct"},
					},
				},
			}

			errs := checkFailoverOutbounds("srv1", cfg)
			if tt.wantError && len(errs) == 0 {
				t.Errorf("expected error for strategy %q, got none", tt.strategy)
			}
			if !tt.wantError && len(errs) != 0 {
				t.Errorf("expected no error for strategy %q, got %v", tt.strategy, errs)
			}
		})
	}
}

func TestCheckFailoverNestedFailover(t *testing.T) {
	t.Parallel()

	cfg := config.Config{
		Outbounds: []config.Outbound{
			{Type: "direct", Tag: "direct"},
			{Type: generate.TypeFailover, Tag: "fo-a", Outbounds: []string{"fo-b"}},
			{Type: generate.TypeFailover, Tag: "fo-b", Outbounds: []string{"direct"}},
		},
	}

	errs := checkFailoverOutbounds("srv1", cfg)
	if len(errs) == 0 {
		t.Fatal("expected error for nested failover, got none")
	}
	found := false
	for _, e := range errs {
		if strings.Contains(e.Error(), "cannot reference another failover") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("error should mention nested failover, got: %v", errs)
	}
}
