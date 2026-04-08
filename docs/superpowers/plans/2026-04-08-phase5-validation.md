# Phase 5 — Validation

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a `validate` command that runs two-phase validation on cheburbox configurations: Phase 1 checks cheburbox.json consistency across all servers, Phase 2 runs sing-box's built-in config check on generated config.json files.

**Architecture:** A new `validate` package contains the validation logic. It reuses `config.Validate()` for per-server schema checks and `generate.BuildGraph()` for cross-server dependency checks (DRY). New consistency checks are implemented in `validate/check.go`: hysteria2 server_name collision, outbound inbound ref validation, urltest/selector outbound group ref validation. Phase 2 reads existing `config.json` files, parses them with sing-box registry-aware JSON unmarshaling, and calls `box.New()` + `instance.Close()` (same as `sing-box check`). The CLI command `cheburbox validate [--server <name>]` follows the same `--server` semantics as `generate` (validate server + transitive deps). Servers without `config.json` are skipped with a warning in Phase 2.

**Tech Stack:** Go stdlib, `github.com/sagernet/sing-box` (box, include, option), `github.com/sagernet/sing/common/json` (registry-aware unmarshaling), `github.com/spf13/cobra` (CLI).

**Design Decisions:**
- Credential validation is intentionally omitted. sing-box check (Phase 2) catches missing/invalid credentials, and new users without credentials is normal behavior (generate creates them).
- `--all` flag is removed. Default behavior validates all servers.
- Phase 2 only runs when `config.json` exists for a server. Missing `config.json` produces a warning, not an error.
- The validate command runs both phases for each server. Phase 1 errors prevent Phase 2 from running for that server (consistency must pass before config check makes sense).
- Consistency checks collect all errors per server (don't stop at first error) to give the user a complete picture.
- sing-box check is run per-server (not on all servers at once) because each server has its own config.json.

---

## File Map

| File | Responsibility |
|------|---------------|
| `validate/check.go` | Types, Phase 1 consistency checks, Phase 2 sing-box check, `ValidateAll`/`ValidateServers` orchestrators |
| `validate/check_test.go` | Unit tests for consistency checks, tests for sing-box check, integration tests with multi-server projects |
| `cmd/cheburbox/main.go` | Updated: add `validate` command with `--server` flag |

---

## Task 1: Consistency Checks — Hysteria2 Server Name Collision

**Files:**
- Create: `validate/check.go`
- Create: `validate/check_test.go`

Add the `validate` package with types and the first new consistency check: no two hysteria2 inbounds on the same server may share the same `tls.server_name` (would conflict on cert files).

- [ ] **Step 1: Write the failing test**

Create `validate/check_test.go`:

```go
package validate

import (
	"testing"

	"github.com/Arsolitt/cheburbox/config"
)

func TestCheckHysteria2ServerNameCollision(t *testing.T) {
	t.Parallel()

	cfg := config.Config{
		Inbounds: []config.Inbound{
			{Tag: "hy2-in-1", Type: "hysteria2", TLS: &config.InboundTLS{ServerName: "example.com"}},
			{Tag: "hy2-in-2", Type: "hysteria2", TLS: &config.InboundTLS{ServerName: "example.com"}},
		},
	}

	errs := checkHysteria2ServerNameCollision("server-a", cfg)
	if len(errs) != 1 {
		t.Fatalf("expected 1 error, got %d: %v", len(errs), errs)
	}
}

func TestCheckHysteria2ServerNameCollisionNoConflict(t *testing.T) {
	t.Parallel()

	cfg := config.Config{
		Inbounds: []config.Inbound{
			{Tag: "hy2-in-1", Type: "hysteria2", TLS: &config.InboundTLS{ServerName: "a.example.com"}},
			{Tag: "hy2-in-2", Type: "hysteria2", TLS: &config.InboundTLS{ServerName: "b.example.com"}},
		},
	}

	errs := checkHysteria2ServerNameCollision("server-a", cfg)
	if len(errs) != 0 {
		t.Fatalf("expected 0 errors, got %d: %v", len(errs), errs)
	}
}

func TestCheckHysteria2ServerNameCollisionNoTLS(t *testing.T) {
	t.Parallel()

	cfg := config.Config{
		Inbounds: []config.Inbound{
			{Tag: "hy2-in", Type: "hysteria2"},
		},
	}

	errs := checkHysteria2ServerNameCollision("server-a", cfg)
	if len(errs) != 0 {
		t.Fatalf("expected 0 errors for hy2 inbound without TLS, got %d: %v", len(errs), errs)
	}
}

func TestCheckHysteria2ServerNameCollisionNonHysteria2(t *testing.T) {
	t.Parallel()

	cfg := config.Config{
		Inbounds: []config.Inbound{
			{Tag: "vless-in", Type: "vless", TLS: &config.InboundTLS{ServerName: "example.com"}},
		},
	}

	errs := checkHysteria2ServerNameCollision("server-a", cfg)
	if len(errs) != 0 {
		t.Fatalf("expected 0 errors for non-hysteria2 inbound, got %d: %v", len(errs), errs)
	}
}

func TestCheckHysteria2ServerNameCollisionThreeWay(t *testing.T) {
	t.Parallel()

	cfg := config.Config{
		Inbounds: []config.Inbound{
			{Tag: "hy2-in-1", Type: "hysteria2", TLS: &config.InboundTLS{ServerName: "example.com"}},
			{Tag: "hy2-in-2", Type: "hysteria2", TLS: &config.InboundTLS{ServerName: "example.com"}},
			{Tag: "hy2-in-3", Type: "hysteria2", TLS: &config.InboundTLS{ServerName: "other.com"}},
		},
	}

	errs := checkHysteria2ServerNameCollision("server-a", cfg)
	if len(errs) != 1 {
		t.Fatalf("expected 1 error, got %d: %v", len(errs), errs)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./validate/ -run TestCheckHysteria2 -v`
Expected: FAIL — `checkHysteria2ServerNameCollision` not defined.

- [ ] **Step 3: Implement checkHysteria2ServerNameCollision**

Create `validate/check.go`:

```go
// Package validate provides two-phase validation for cheburbox configurations.
// Phase 1 runs consistency checks on cheburbox.json across all servers.
// Phase 2 runs sing-box's built-in config check on generated config.json files.
package validate

import (
	"fmt"

	"github.com/Arsolitt/cheburbox/config"
)

func checkHysteria2ServerNameCollision(server string, cfg config.Config) []error {
	var errs []error

	seen := make(map[string]string)

	for _, in := range cfg.Inbounds {
		if in.Type != "hysteria2" {
			continue
		}
		if in.TLS == nil || in.TLS.ServerName == "" {
			continue
		}

		if prev, ok := seen[in.TLS.ServerName]; ok {
			errs = append(errs, fmt.Errorf(
				"server %q: hysteria2 inbounds %q and %q share the same tls.server_name %q (would conflict on cert files)",
				server, prev, in.Tag, in.TLS.ServerName,
			))
			continue
		}

		seen[in.TLS.ServerName] = in.Tag
	}

	return errs
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./validate/ -run TestCheckHysteria2 -v`
Expected: PASS

- [ ] **Step 5: Run linter**

Run: `golangci-lint run --fix`

- [ ] **Step 6: Commit**

```bash
git add validate/check.go validate/check_test.go
git commit -m "feat(validate): add hysteria2 server_name collision check"
```

---

## Task 2: Consistency Checks — Outbound Inbound Ref and Outbound Group Ref

**Files:**
- Modify: `validate/check.go`
- Modify: `validate/check_test.go`

Add two more consistency checks:
1. Outbound `inbound` references an existing inbound tag on the target server.
2. `urltest` and `selector` outbound groups reference only outbound tags that exist in the same server's outbound list.

- [ ] **Step 1: Write the failing tests**

Add to `validate/check_test.go`:

```go
func TestCheckOutboundInboundRefs(t *testing.T) {
	t.Parallel()

	configs := map[string]config.Config{
		"server-a": {
			Outbounds: []config.Outbound{
				{Type: "vless", Tag: "out-a", Server: "server-b", Inbound: "vless-in"},
			},
		},
		"server-b": {
			Inbounds: []config.Inbound{
				{Tag: "vless-in", Type: "vless"},
			},
			Outbounds: []config.Outbound{
				{Type: "direct", Tag: "direct"},
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
				{Type: "vless", Tag: "out-a", Server: "server-b", Inbound: "nonexistent-in"},
			},
		},
		"server-b": {
			Inbounds: []config.Inbound{
				{Tag: "vless-in", Type: "vless"},
			},
		},
	}

	errs := checkOutboundInboundRefs(configs)
	if len(errs) != 1 {
		t.Fatalf("expected 1 error, got %d: %v", len(errs), errs)
	}
}

func TestCheckOutboundInboundRefsNoCrossServer(t *testing.T) {
	t.Parallel()

	configs := map[string]config.Config{
		"server-a": {
			Outbounds: []config.Outbound{
				{Type: "direct", Tag: "direct"},
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
			{Type: "vless", Tag: "vless-out"},
			{Type: "hysteria2", Tag: "hy2-out"},
			{Type: "urltest", Tag: "proxy", Outbounds: []string{"vless-out", "hy2-out"}},
			{Type: "selector", Tag: "selector", Outbounds: []string{"vless-out", "hy2-out", "direct"}},
		},
	}

	errs := checkOutboundGroupRefs("server-a", cfg)
	if len(errs) != 0 {
		t.Fatalf("expected 0 errors, got %d: %v", len(errs), errs)
	}
}

func TestCheckOutboundGroupRefsInvalid(t *testing.T) {
	t.Parallel()

	cfg := config.Config{
		Outbounds: []config.Outbound{
			{Type: "direct", Tag: "direct"},
			{Type: "urltest", Tag: "proxy", Outbounds: []string{"vless-out", "nonexistent"}},
		},
	}

	errs := checkOutboundGroupRefs("server-a", cfg)
	if len(errs) != 1 {
		t.Fatalf("expected 1 error, got %d: %v", len(errs), errs)
	}
}

func TestCheckOutboundGroupRefsNonGroupOutbound(t *testing.T) {
	t.Parallel()

	cfg := config.Config{
		Outbounds: []config.Outbound{
			{Type: "direct", Tag: "direct"},
			{Type: "vless", Tag: "vless-out"},
		},
	}

	errs := checkOutboundGroupRefs("server-a", cfg)
	if len(errs) != 0 {
		t.Fatalf("expected 0 errors, got %d: %v", len(errs), errs)
	}
}

func TestCheckOutboundGroupRefsEmptyOutbounds(t *testing.T) {
	t.Parallel()

	cfg := config.Config{
		Outbounds: []config.Outbound{
			{Type: "urltest", Tag: "proxy"},
		},
	}

	errs := checkOutboundGroupRefs("server-a", cfg)
	if len(errs) != 0 {
		t.Fatalf("expected 0 errors for empty outbounds list, got %d: %v", len(errs), errs)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./validate/ -run "TestCheckOutboundInboundRefs|TestCheckOutboundGroupRefs" -v`
Expected: FAIL — `checkOutboundInboundRefs`, `checkOutboundGroupRefs` not defined.

- [ ] **Step 3: Implement outbound inbound ref check and outbound group ref check**

Add to `validate/check.go`:

```go
func checkOutboundInboundRefs(configs map[string]config.Config) []error {
	var errs []error

	inboundTags := make(map[string]map[string]bool)
	for name, cfg := range configs {
		tags := make(map[string]bool, len(cfg.Inbounds))
		for _, in := range cfg.Inbounds {
			tags[in.Tag] = true
		}
		inboundTags[name] = tags
	}

	for name, cfg := range configs {
		for _, out := range cfg.Outbounds {
			if out.Server == "" || out.Inbound == "" {
				continue
			}

			targetTags, ok := inboundTags[out.Server]
			if !ok {
				continue
			}

			if !targetTags[out.Inbound] {
				errs = append(errs, fmt.Errorf(
					"server %q outbound %q references inbound %q on server %q, but no such inbound exists",
					name, out.Tag, out.Inbound, out.Server,
				))
			}
		}
	}

	return errs
}

func checkOutboundGroupRefs(server string, cfg config.Config) []error {
	var errs []error

	validTags := make(map[string]bool, len(cfg.Outbounds))
	for _, out := range cfg.Outbounds {
		validTags[out.Tag] = true
	}

	for _, out := range cfg.Outbounds {
		if out.Type != "urltest" && out.Type != "selector" {
			continue
		}

		for _, ref := range out.Outbounds {
			if !validTags[ref] {
				errs = append(errs, fmt.Errorf(
					"server %q %s outbound %q references unknown outbound %q",
					server, out.Type, out.Tag, ref,
				))
			}
		}
	}

	return errs
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./validate/ -run "TestCheckOutboundInboundRefs|TestCheckOutboundGroupRefs" -v`
Expected: PASS

- [ ] **Step 5: Run linter**

Run: `golangci-lint run --fix`

- [ ] **Step 6: Commit**

```bash
git add validate/check.go validate/check_test.go
git commit -m "feat(validate): add outbound inbound ref and outbound group ref checks"
```

---

## Task 3: sing-box Config Check (Phase 2)

**Files:**
- Modify: `validate/check.go`
- Modify: `validate/check_test.go`

Add the sing-box config check function that reads an existing `config.json`, parses it with registry-aware unmarshaling, creates a `box.New()` instance, and immediately closes it. This replicates the `sing-box check` command behavior.

- [ ] **Step 1: Write the failing test**

Add to `validate/check_test.go`:

```go
import (
	"os"
	"path/filepath"
	"strings"

	"github.com/Arsolitt/cheburbox/generate"
)

func TestSingBoxCheckValidConfig(t *testing.T) {
	t.Parallel()

	projectRoot := t.TempDir()

	setupTestServer(t, projectRoot, "test-server", config.Config{
		Version:  1,
		Endpoint: "1.2.3.4",
		DNS: config.DNS{
			Final:   ptr("dns-local"),
			Servers: []config.DNSServer{{Type: "local", Tag: "dns-local"}},
		},
		Outbounds: []config.Outbound{
			{Type: "direct", Tag: "direct"},
		},
	})

	dir := filepath.Join(projectRoot, "test-server")
	cfg, err := config.LoadServerWithJsonnet(dir, "")
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	result, err := generate.GenerateServer(dir, cfg, generate.GenerateConfig{})
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	configFile := findGenerateFile(result.Files, "config.json")
	if configFile == nil {
		t.Fatal("config.json not found in generate result")
	}

	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.json")
	if err := os.WriteFile(configPath, configFile.Content, 0o644); err != nil {
		t.Fatalf("write config.json: %v", err)
	}

	err = singBoxCheck(configPath)
	if err != nil {
		t.Fatalf("singBoxCheck: expected no error for valid config, got: %v", err)
	}
}

func TestSingBoxCheckInvalidConfig(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.json")

	invalidJSON := `{"inbounds": [{"type": "invalid_type", "tag": "bad"}]}`
	if err := os.WriteFile(configPath, []byte(invalidJSON), 0o644); err != nil {
		t.Fatalf("write config.json: %v", err)
	}

	err := singBoxCheck(configPath)
	if err == nil {
		t.Fatal("singBoxCheck: expected error for invalid config")
	}
}

func TestSingBoxCheckMissingFile(t *testing.T) {
	t.Parallel()

	err := singBoxCheck("/nonexistent/path/config.json")
	if err == nil {
		t.Fatal("singBoxCheck: expected error for missing file")
	}
	if !strings.Contains(err.Error(), "read config.json") {
		t.Errorf("error should mention reading file, got: %v", err)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./validate/ -run TestSingBoxCheck -v`
Expected: FAIL — `singBoxCheck`, `findGenerateFile`, `ptr` not defined.

- [ ] **Step 3: Implement singBoxCheck and helpers**

Add to `validate/check.go`:

```go
import (
	"context"
	"fmt"
	"os"

	"github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/include"
	singjson "github.com/sagernet/sing/common/json"

	"github.com/Arsolitt/cheburbox/generate"
)

func singBoxCheck(configPath string) error {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("read config.json: %w", err)
	}

	ctx := include.Context(context.Background())

	var opts box.Options
	if err := singjson.UnmarshalContext(ctx, data, &opts.Options); err != nil {
		return fmt.Errorf("parse config.json: %w", err)
	}

	instance, err := box.New(box.Options{
		Context: ctx,
		Options: opts.Options,
	})
	if err != nil {
		return fmt.Errorf("sing-box check: %w", err)
	}

	instance.Close()

	return nil
}

func findGenerateFile(files []generate.FileOutput, path string) *generate.FileOutput {
	for i := range files {
		if files[i].Path == path {
			return &files[i]
		}
	}
	return nil
}

func ptr(s string) *string {
	return &s
}
```

> **Note:** The `singjson.UnmarshalContext` call parses JSON into `option.Options` using the registry-aware context. If the JSON contains protocol-specific options (vless, hysteria2, etc.), the registry in the context is used to unmarshal them correctly. If `UnmarshalContext` doesn't handle nested types properly, try `singjson.UnmarshalExtendedContext[option.Options](ctx, data)` instead.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./validate/ -run TestSingBoxCheck -v`
Expected: PASS (valid config passes, invalid config fails, missing file fails)

- [ ] **Step 5: Run linter**

Run: `golangci-lint run --fix`

- [ ] **Step 6: Commit**

```bash
git add validate/check.go validate/check_test.go
git commit -m "feat(validate): add sing-box config check (Phase 2)"
```

---

## Task 4: ValidateAll and ValidateServers Orchestrators

**Files:**
- Modify: `validate/check.go`
- Modify: `validate/check_test.go`

Add the top-level orchestrator functions that tie Phase 1 and Phase 2 together, plus the `ServerResult` type for reporting.

- [ ] **Step 1: Write the failing tests**

Add to `validate/check_test.go`:

```go
func TestValidateAllPhase1Only(t *testing.T) {
	t.Parallel()

	projectRoot := t.TempDir()

	setupTestServer(t, projectRoot, "srv-a", config.Config{
		Version:  1,
		Endpoint: "1.2.3.4",
		DNS: config.DNS{
			Final:   ptr("dns-local"),
			Servers: []config.DNSServer{{Type: "local", Tag: "dns-local"}},
		},
		Outbounds: []config.Outbound{
			{Type: "direct", Tag: "direct"},
		},
	})

	results, err := ValidateAll(projectRoot, "")
	if err != nil {
		t.Fatalf("ValidateAll: %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}

	if results[0].Server != "srv-a" {
		t.Errorf("server = %q, want srv-a", results[0].Server)
	}

	if results[0].Failed() {
		t.Errorf("expected server to pass, got errors: %v", results[0].Errors)
	}
}

func TestValidateAllPhase1Errors(t *testing.T) {
	t.Parallel()

	projectRoot := t.TempDir()

	setupTestServer(t, projectRoot, "srv-a", config.Config{
		Version: 0,
		DNS:     config.DNS{},
	})

	results, err := ValidateAll(projectRoot, "")
	if err != nil {
		t.Fatalf("ValidateAll: %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}

	if !results[0].Failed() {
		t.Error("expected server to fail validation")
	}

	if len(results[0].Errors) == 0 {
		t.Error("expected at least one error")
	}
}

func TestValidateAllWithCycle(t *testing.T) {
	t.Parallel()

	projectRoot := t.TempDir()

	setupTestServer(t, projectRoot, "srv-a", config.Config{
		Version: 1,
		DNS: config.DNS{
			Final:   ptr("dns-local"),
			Servers: []config.DNSServer{{Type: "local", Tag: "dns-local"}},
		},
		Outbounds: []config.Outbound{
			{Type: "vless", Tag: "out", Server: "srv-b", Inbound: "vless-in"},
		},
	})

	setupTestServer(t, projectRoot, "srv-b", config.Config{
		Version: 1,
		DNS: config.DNS{
			Final:   ptr("dns-local"),
			Servers: []config.DNSServer{{Type: "local", Tag: "dns-local"}},
		},
		Outbounds: []config.Outbound{
			{Type: "vless", Tag: "out", Server: "srv-a", Inbound: "vless-in"},
		},
	})

	_, err := ValidateAll(projectRoot, "")
	if err == nil {
		t.Fatal("expected error for cycle")
	}
}

func TestValidateAllEmptyProject(t *testing.T) {
	t.Parallel()

	projectRoot := t.TempDir()

	results, err := ValidateAll(projectRoot, "")
	if err != nil {
		t.Fatalf("ValidateAll: %v", err)
	}

	if len(results) != 0 {
		t.Fatalf("expected 0 results for empty project, got %d", len(results))
	}
}

func TestValidateServersWithServerFlag(t *testing.T) {
	t.Parallel()

	projectRoot := t.TempDir()

	setupTestServer(t, projectRoot, "srv-a", config.Config{
		Version:  1,
		Endpoint: "1.2.3.4",
		DNS: config.DNS{
			Final:   ptr("dns-local"),
			Servers: []config.DNSServer{{Type: "local", Tag: "dns-local"}},
		},
		Outbounds: []config.Outbound{
			{Type: "direct", Tag: "direct"},
		},
	})

	setupTestServer(t, projectRoot, "srv-b", config.Config{
		Version:  1,
		DNS: config.DNS{
			Final:   ptr("dns-local"),
			Servers: []config.DNSServer{{Type: "local", Tag: "dns-local"}},
		},
		Outbounds: []config.Outbound{
			{Type: "direct", Tag: "direct"},
		},
	})

	results, err := ValidateServers(projectRoot, "", "srv-a")
	if err != nil {
		t.Fatalf("ValidateServers: %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("expected 1 result (srv-a only), got %d", len(results))
	}

	if results[0].Server != "srv-a" {
		t.Errorf("server = %q, want srv-a", results[0].Server)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./validate/ -run "TestValidateAll|TestValidateServers" -v`
Expected: FAIL — `ValidateAll`, `ValidateServers`, `ServerResult`, `Failed` not defined.

- [ ] **Step 3: Implement ServerResult, ValidateAll, ValidateServers**

Add to `validate/check.go`:

```go
import (
	"path/filepath"

	"github.com/Arsolitt/cheburbox/config"
	"github.com/Arsolitt/cheburbox/generate"
)

type ServerResult struct {
	Server   string
	Errors   []error
	Warnings []string
}

func (r *ServerResult) Failed() bool {
	return len(r.Errors) > 0
}

func ValidateAll(projectRoot string, jpath string) ([]ServerResult, error) {
	servers, err := config.Discover(projectRoot)
	if err != nil {
		return nil, fmt.Errorf("discover servers: %w", err)
	}

	if len(servers) == 0 {
		return nil, nil
	}

	configs, err := loadConfigs(servers, projectRoot, jpath)
	if err != nil {
		return nil, err
	}

	return runPhase1AndPhase2(configs, projectRoot)
}

func ValidateServers(projectRoot string, jpath string, serverName string) ([]ServerResult, error) {
	allServers, err := config.Discover(projectRoot)
	if err != nil {
		return nil, fmt.Errorf("discover servers: %w", err)
	}

	allConfigs, err := loadConfigs(allServers, projectRoot, jpath)
	if err != nil {
		return nil, err
	}

	graph, err := generate.BuildGraph(allConfigs)
	if err != nil {
		return nil, fmt.Errorf("build dependency graph: %w", err)
	}

	deps, err := graph.TransitiveDependencies(serverName)
	if err != nil {
		return nil, fmt.Errorf("resolve dependencies for %s: %w", serverName, err)
	}

	configs := make(map[string]config.Config, len(deps))
	for _, dep := range deps {
		configs[dep] = allConfigs[dep]
	}

	return runPhase1AndPhase2(configs, projectRoot)
}

func runPhase1AndPhase2(configs map[string]config.Config, projectRoot string) ([]ServerResult, error) {
	phase1Results := runPhase1(configs)

	results := make([]ServerResult, 0, len(phase1Results))
	for _, r := range phase1Results {
		if r.Failed() {
			results = append(results, r)
			continue
		}

		runPhase2(&r, projectRoot)
		results = append(results, r)
	}

	return results, nil
}

func runPhase1(configs map[string]config.Config) []ServerResult {
	graph, err := generate.BuildGraph(configs)
	if err != nil {
		return []ServerResult{{
			Server: "(global)",
			Errors: []error{err},
		}}
	}

	results := make([]ServerResult, 0, len(configs))

	for name, cfg := range configs {
		r := ServerResult{Server: name}

		if err := config.Validate(cfg); err != nil {
			r.Errors = append(r.Errors, err)
		}

		r.Errors = append(r.Errors, checkHysteria2ServerNameCollision(name, cfg)...)
		r.Errors = append(r.Errors, checkOutboundInboundRefs(configs)...)
		r.Errors = append(r.Errors, checkOutboundGroupRefs(name, cfg)...)

		results = append(results, r)
	}

	_ = graph

	return results
}

func runPhase2(r *ServerResult, projectRoot string) {
	configPath := filepath.Join(projectRoot, r.Server, "config.json")

	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		r.Warnings = append(r.Warnings, fmt.Sprintf("skipped sing-box check: %s/config.json not found", r.Server))
		return
	}

	if err := singBoxCheck(configPath); err != nil {
		r.Errors = append(r.Errors, err)
	}
}

func loadConfigs(
	servers []string,
	projectRoot string,
	jpath string,
) (map[string]config.Config, error) {
	configs := make(map[string]config.Config, len(servers))

	for _, name := range servers {
		dir := filepath.Join(projectRoot, name)
		cfg, err := config.LoadServerWithJsonnet(dir, jpath)
		if err != nil {
			return nil, fmt.Errorf("load config for %s: %w", name, err)
		}
		configs[name] = cfg
	}

	return configs, nil
}
```

> **Note:** `runPhase1` currently calls `config.Validate(cfg)` per server (which already does version/DNS/endpoint checks), then calls the new checks. The `generate.BuildGraph` call is kept to reuse cycle detection and unknown server ref checks, but its graph result is not currently used. The graph errors (cycles, unknown refs) are caught by `BuildGraph` itself. The `_ = graph` suppresses the unused variable linter.

> **Important optimization:** `checkOutboundInboundRefs` is called once per server in the loop but takes the full `configs` map. This means it runs N times for N servers, checking all cross-server refs each time. To avoid duplicate errors, the implementation should either deduplicate or call it once outside the loop. The simplest fix: call `checkOutboundInboundRefs(configs)` once before the loop and distribute errors to the relevant servers.

- [ ] **Step 4: Fix the duplicate checkOutboundInboundRefs issue**

Update `runPhase1` in `validate/check.go` to call cross-server checks once:

```go
func runPhase1(configs map[string]config.Config) []ServerResult {
	graph, err := generate.BuildGraph(configs)
	if err != nil {
		return []ServerResult{{
			Server: "(global)",
			Errors: []error{err},
		}}
	}

	crossServerErrs := checkOutboundInboundRefs(configs)

	results := make([]ServerResult, 0, len(configs))

	for name, cfg := range configs {
		r := ServerResult{Server: name}

		if err := config.Validate(cfg); err != nil {
			r.Errors = append(r.Errors, err)
		}

		r.Errors = append(r.Errors, checkHysteria2ServerNameCollision(name, cfg)...)
		r.Errors = append(r.Errors, checkOutboundGroupRefs(name, cfg)...)

		for _, e := range crossServerErrs {
			if strings.Contains(e.Error(), fmt.Sprintf("server %q ", name)) {
				r.Errors = append(r.Errors, e)
			}
		}

		results = append(results, r)
	}

	_ = graph

	return results
}
```

Add `"strings"` to the imports of `validate/check.go`.

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test ./validate/ -run "TestValidateAll|TestValidateServers" -v`
Expected: PASS

- [ ] **Step 6: Run linter**

Run: `golangci-lint run --fix`

- [ ] **Step 7: Commit**

```bash
git add validate/check.go validate/check_test.go
git commit -m "feat(validate): add ValidateAll and ValidateServers orchestrators"
```

---

## Task 5: CLI Command — `validate`

**Files:**
- Modify: `cmd/cheburbox/main.go`

Add the `validate` subcommand to the CLI.

- [ ] **Step 1: Add the validate command**

Add to `cmd/cheburbox/main.go`:

Import `"github.com/Arsolitt/cheburbox/validate"`.

Add the following before the `return rootCmd` line in `NewRootCommand`:

```go
	var validateServer string

	validateCmd := &cobra.Command{
		Use:   "validate",
		Short: "Validate cheburbox configurations without generating files.",
		RunE: func(command *cobra.Command, _ []string) error {
			proj := projectRoot
			if proj == "" {
				var err error
				proj, err = os.Getwd()
				if err != nil {
					return fmt.Errorf("get working directory: %w", err)
				}
			}
			return runValidate(command.OutOrStdout(), proj, jpath, validateServer)
		},
	}

	validateCmd.Flags().StringVar(&validateServer, "server", "", "validate only this server and its dependencies")
	rootCmd.AddCommand(validateCmd)
```

Add the `runValidate` function:

```go
func runValidate(w io.Writer, projectRoot string, jpath string, serverName string) error {
	jpathAbs := resolveJPath(projectRoot, jpath)

	var results []validate.ServerResult
	var err error

	if serverName != "" {
		results, err = validate.ValidateServers(projectRoot, jpathAbs, serverName)
	} else {
		results, err = validate.ValidateAll(projectRoot, jpathAbs)
	}

	if err != nil {
		return err
	}

	if len(results) == 0 {
		fmt.Fprintln(w, "no servers found in project")
		return nil
	}

	hasErrors := false

	for _, r := range results {
		for _, warn := range r.Warnings {
			fmt.Fprintf(w, "WARN  %s: %s\n", r.Server, warn)
		}

		if r.Failed() {
			hasErrors = true
			for _, e := range r.Errors {
				fmt.Fprintf(w, "FAIL  %s: %s\n", r.Server, e)
			}
		} else {
			fmt.Fprintf(w, "PASS  %s\n", r.Server)
		}
	}

	if hasErrors {
		return fmt.Errorf("validation failed")
	}

	return nil
}
```

- [ ] **Step 2: Build and verify**

Run: `go build -o build/cheburbox ./cmd/cheburbox/`
Expected: Build succeeds.

- [ ] **Step 3: Run linter**

Run: `golangci-lint run --fix`

- [ ] **Step 4: Commit**

```bash
git add cmd/cheburbox/main.go
git commit -m "feat(cli): add validate command with --server flag"
```

---

## Task 6: Integration Test — Full Pipeline

**Files:**
- Modify: `validate/check_test.go`

Add an integration test that creates a multi-server project, generates configs, then validates them end-to-end.

- [ ] **Step 1: Write the integration test**

Add to `validate/check_test.go`:

```go
func TestValidateAllWithGeneratedConfigs(t *testing.T) {
	t.Parallel()

	projectRoot := t.TempDir()

	exitCfg := config.Config{
		Version:  1,
		Endpoint: "10.0.0.1",
		DNS: config.DNS{
			Final:   ptr("dns-local"),
			Servers: []config.DNSServer{{Type: "local", Tag: "dns-local"}},
		},
		Inbounds: []config.Inbound{
			{
				Tag:        "vless-in",
				Type:       "vless",
				ListenPort: 443,
				Users:      []config.InboundUser{{Name: "proxy-server"}},
				TLS: &config.InboundTLS{
					Reality: &config.RealityConfig{
						Handshake: &config.RealityHandshake{
							Server:     "example.com",
							ServerPort: 443,
						},
					},
				},
			},
		},
		Outbounds: []config.Outbound{
			{Type: "direct", Tag: "direct"},
		},
	}

	proxyCfg := config.Config{
		Version: 1,
		DNS: config.DNS{
			Final:   ptr("dns-local"),
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
			Final:   ptr("dns-local"),
			Servers: []config.DNSServer{{Type: "local", Tag: "dns-local"}},
		},
		Outbounds: []config.Outbound{
			{Type: "direct", Tag: "direct"},
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
		t.Errorf("expected 1 warning (skipped sing-box check), got %d: %v", len(results[0].Warnings), results[0].Warnings)
	}
}
```

Add the `setupTestServer` helper if not already present (it may already exist from Task 1):

```go
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
```

> **Note:** Make sure `"encoding/json"`, `"os"`, `"path/filepath"` are imported in the test file.

- [ ] **Step 2: Run tests to verify they pass**

Run: `go test ./validate/ -v`
Expected: ALL PASS

- [ ] **Step 3: Run linter**

Run: `golangci-lint run --fix`

- [ ] **Step 4: Commit**

```bash
git add validate/check_test.go
git commit -m "test(validate): add integration tests for full validation pipeline"
```

---

## Task 7: Final Verification

**Files:** None (verification only)

- [ ] **Step 1: Run all tests**

Run: `go test ./...`
Expected: ALL PASS

- [ ] **Step 2: Run linter**

Run: `golangci-lint run --fix`
Expected: no errors.

- [ ] **Step 3: Build binary**

Run: `go build -o build/cheburbox ./cmd/cheburbox/`
Expected: Build succeeds.

- [ ] **Step 4: Verify CLI help**

Run: `./build/cheburbox validate --help`
Expected: Shows validate command help with `--server` flag.
