# Phase 3 — Rule-Sets

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement local rule-set compilation (`.json` → `.srs`) using sing-box `common/srs` package, auto-compile during `generate`, and add a standalone `rule-set compile` CLI command.

**Architecture:** New `ruleset` package wraps sing-box `srs.Write` to compile JSON rule-set source files into binary `.srs` format. The `generate` package calls this during `GenerateServer` to auto-compile rule-set sources found in the server directory. The `route.go` conversion is updated to reference `.srs` files instead of `.json`. A new `rule-set compile` cobra subcommand provides standalone compilation.

**Tech Stack:** `github.com/sagernet/sing-box/common/srs` (binary write), `github.com/sagernet/sing-box/constant` (version/format constants), `github.com/sagernet/sing-box/option` (PlainRuleSetCompat), `github.com/sagernet/sing/common/json` (UnmarshalExtended), `github.com/spf13/cobra` (CLI command).

**Design Decisions:**
- Rule-set source files (`*.json`) live directly in the server directory (e.g., `extension.json`). Compiled `.srs` files go into a `rule-set/` subdirectory (e.g., `rule-set/extension.srs`). This keeps the design doc's directory structure consistent.
- sing-box auto-detects format from file extension: `.srs` → binary, `.json` → source. No need to set `Format` explicitly in the generated config.
- `option.PlainRuleSetCompat` supports a `"version"` field in the JSON source. The compile function reads it and passes the version to `srs.Write`. If omitted, defaults to `RuleSetVersionCurrent`.
- Custom rule-set path in generated config changes from `rule-set/<name>.json` to `rule-set/<name>.srs`.
- Source discovery: scan the server directory for `*.json` files that are NOT `cheburbox.json`, `config.json`, or `.cheburbox.jsonnet`. Match them against `CustomRuleSets` names.

---

## File Map

| File | Responsibility |
|------|---------------|
| `ruleset/compile.go` | Compile JSON rule-set source → binary `.srs` via `srs.Write` |
| `ruleset/compile_test.go` | Tests for compile function with sample rule-set JSON |
| `ruleset/discover.go` | Find rule-set source files in server directory, match against CustomRuleSets |
| `ruleset/discover_test.go` | Tests for discovery logic |
| `generate/route.go` | Updated: custom rule-set path from `.json` to `.srs` |
| `generate/server.go` | Updated: auto-compile rule-sets during generation, add `.srs` files to output |
| `generate/route_test.go` | Updated: assert `.srs` path instead of `.json` |
| `generate/server_test.go` | Updated: verify rule-set files in generation output |
| `cmd/cheburbox/main.go` | Updated: add `rule-set compile` subcommand |

---

## Task 1: Create `ruleset` Package — Compile Function

**Files:**
- Create: `ruleset/compile.go`
- Create: `ruleset/compile_test.go`

- [ ] **Step 1: Write the failing test for `Compile`**

Create `ruleset/compile_test.go`:

```go
package ruleset

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCompile(t *testing.T) {
	t.Parallel()

	input := `{
  "rules": [
    {
      "domain_suffix": [
        ".example.com",
        ".test.org"
      ]
    },
    {
      "ip_cidr": [
        "10.0.0.0/8",
        "172.16.0.0/12"
      ]
    }
  ]
}`

	outputDir := t.TempDir()
	outputPath := filepath.Join(outputDir, "test.srs")

	if err := Compile([]byte(input), outputPath); err != nil {
		t.Fatalf("Compile: %v", err)
	}

	info, err := os.Stat(outputPath)
	if err != nil {
		t.Fatalf("stat output: %v", err)
	}
	if info.Size() == 0 {
		t.Fatal("output file is empty")
	}
}

func TestCompileWithVersion(t *testing.T) {
	t.Parallel()

	input := `{
  "version": 4,
  "rules": [
    {
      "domain_keyword": ["ads"]
    }
  ]
}`

	outputDir := t.TempDir()
	outputPath := filepath.Join(outputDir, "versioned.srs")

	if err := Compile([]byte(input), outputPath); err != nil {
		t.Fatalf("Compile: %v", err)
	}

	if _, err := os.Stat(outputPath); err != nil {
		t.Fatalf("stat output: %v", err)
	}
}

func TestCompileEmptyRules(t *testing.T) {
	t.Parallel()

	input := `{"rules": []}`

	outputDir := t.TempDir()
	outputPath := filepath.Join(outputDir, "empty.srs")

	if err := Compile([]byte(input), outputPath); err != nil {
		t.Fatalf("Compile: %v", err)
	}
}

func TestCompileInvalidJSON(t *testing.T) {
	t.Parallel()

	input := `{invalid json}`

	outputDir := t.TempDir()
	outputPath := filepath.Join(outputDir, "bad.srs")

	if err := Compile([]byte(input), outputPath); err == nil {
		t.Fatal("expected error for invalid JSON, got nil")
	}
}

func TestCompileInvalidOutputPath(t *testing.T) {
	t.Parallel()

	input := `{"rules": []}`

	if err := Compile([]byte(input), "/nonexistent/dir/test.srs"); err == nil {
		t.Fatal("expected error for invalid output path, got nil")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
go test ./ruleset/ -v -run TestCompile
```

Expected: FAIL — `ruleset` package does not exist.

- [ ] **Step 3: Implement `Compile` function**

Create `ruleset/compile.go`:

```go
// Package ruleset provides compilation of local sing-box rule-sets
// from JSON source format to binary .srs format.
package ruleset

import (
	"fmt"
	"os"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/common/srs"
	"github.com/sagernet/sing-box/option"
	singjson "github.com/sagernet/sing/common/json"
)

// Compile reads a JSON rule-set source and writes a binary .srs file.
// The input must be a valid sing-box rule-set JSON with a "rules" array.
// An optional "version" field controls the SRS format version; if omitted,
// RuleSetVersionCurrent is used.
func Compile(input []byte, outputPath string) error {
	plainRuleSet, err := singjson.UnmarshalExtended[option.PlainRuleSetCompat](input)
	if err != nil {
		return fmt.Errorf("parse rule-set JSON: %w", err)
	}

	version := plainRuleSet.Version
	if version == 0 {
		version = C.RuleSetVersionCurrent
	}

	outputFile, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("create output file: %w", err)
	}
	defer outputFile.Close()

	if err := srs.Write(outputFile, plainRuleSet.Options, version); err != nil {
		return fmt.Errorf("write .srs: %w", err)
	}

	return nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
go test ./ruleset/ -v -run TestCompile
```

Expected: All 5 tests PASS.

- [ ] **Step 5: Run linter**

```bash
golangci-lint run --fix
```

Expected: no errors.

- [ ] **Step 6: Commit**

```bash
git add ruleset/
git commit -m "feat(ruleset): add Compile function for JSON-to-SRS conversion"
```

---

## Task 2: Create `ruleset` Package — Discovery

**Files:**
- Create: `ruleset/discover.go`
- Create: `ruleset/discover_test.go`

- [ ] **Step 1: Write the failing test for `FindSourceFiles`**

Create `ruleset/discover_test.go`:

```go
package ruleset

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFindSourceFiles(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	writeFile(t, dir, "extension.json", `{"rules": [{"domain_suffix": [".example.com"]}]}`)
	writeFile(t, dir, "fastly.json", `{"rules": [{"ip_cidr": ["10.0.0.0/8"]}]}`)
	writeFile(t, dir, "config.json", `{"inbounds": []}`)
	writeFile(t, dir, ".cheburbox.jsonnet", `local x = {}; {}`)

	customRuleSets := []string{"extension", "fastly"}
	sources, err := FindSourceFiles(dir, customRuleSets)
	if err != nil {
		t.Fatalf("FindSourceFiles: %v", err)
	}

	if len(sources) != 2 {
		t.Fatalf("expected 2 source files, got %d", len(sources))
	}

	for _, name := range customRuleSets {
		found := false
		for _, s := range sources {
			if s.Name == name {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("source file for %q not found", name)
		}
	}
}

func TestFindSourceFilesPartial(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	writeFile(t, dir, "extension.json", `{"rules": []}`)

	sources, err := FindSourceFiles(dir, []string{"extension", "fastly"})
	if err != nil {
		t.Fatalf("FindSourceFiles: %v", err)
	}

	if len(sources) != 1 {
		t.Fatalf("expected 1 source file, got %d", len(sources))
	}
	if sources[0].Name != "extension" {
		t.Errorf("Name = %q, want %q", sources[0].Name, "extension")
	}
}

func TestFindSourceFilesNone(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	sources, err := FindSourceFiles(dir, []string{"missing"})
	if err != nil {
		t.Fatalf("FindSourceFiles: %v", err)
	}

	if len(sources) != 0 {
		t.Errorf("expected 0 source files, got %d", len(sources))
	}
}

func TestFindSourceFilesEmptyDir(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	sources, err := FindSourceFiles(dir, nil)
	if err != nil {
		t.Fatalf("FindSourceFiles: %v", err)
	}

	if len(sources) != 0 {
		t.Errorf("expected 0 source files for empty dir, got %d", len(sources))
	}
}

func writeFile(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
go test ./ruleset/ -v -run TestFindSourceFiles
```

Expected: FAIL — `FindSourceFiles` not defined.

- [ ] **Step 3: Implement `FindSourceFiles` and `SourceFile`**

Add to `ruleset/discover.go`:

```go
package ruleset

import (
	"fmt"
	"os"
	"path/filepath"
)

// SourceFile represents a discovered rule-set source file in a server directory.
type SourceFile struct {
	Name string
	Path string
}

// FindSourceFiles scans the server directory for JSON rule-set source files
// matching the given custom rule-set names. For each name, it looks for
// `<name>.json` in the directory. Files that are cheburbox.json, config.json,
// or .cheburbox.jsonnet are never treated as rule-set sources.
func FindSourceFiles(dir string, customRuleSets []string) ([]SourceFile, error) {
	if len(customRuleSets) == 0 {
		return nil, nil
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read directory: %w", err)
	}

	existing := make(map[string]string, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		ext := filepath.Ext(entry.Name())
		if ext != ".json" {
			continue
		}
		base := entry.Name()[:len(entry.Name())-len(ext)]
		if isReservedFilename(base) {
			continue
		}
		existing[base] = filepath.Join(dir, entry.Name())
	}

	sources := make([]SourceFile, 0, len(customRuleSets))
	for _, name := range customRuleSets {
		path, ok := existing[name]
		if !ok {
			continue
		}
		sources = append(sources, SourceFile{Name: name, Path: path})
	}

	return sources, nil
}

func isReservedFilename(base string) bool {
	switch base {
	case "cheburbox", "config":
		return true
	default:
		return false
	}
}
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
go test ./ruleset/ -v -run TestFindSourceFiles
```

Expected: All 4 tests PASS.

- [ ] **Step 5: Run linter**

```bash
golangci-lint run --fix
```

Expected: no errors.

- [ ] **Step 6: Commit**

```bash
git add ruleset/discover.go ruleset/discover_test.go
git commit -m "feat(ruleset): add FindSourceFiles for rule-set source discovery"
```

---

## Task 3: Update Route Conversion — `.srs` Paths

**Files:**
- Modify: `generate/route.go:50-51`
- Modify: `generate/route_test.go:82-87,103-111`

- [ ] **Step 1: Update `ConvertRoute` to use `.srs` extension**

In `generate/route.go`, change the `LocalOptions.Path` from `.json` to `.srs`:

```go
// Before:
			LocalOptions: option.LocalRuleSet{
				Path: filepath.Join("rule-set", name+".json"),
			},

// After:
			LocalOptions: option.LocalRuleSet{
				Path: filepath.Join("rule-set", name+".srs"),
			},
```

- [ ] **Step 2: Run existing route tests to see them fail**

```bash
go test ./generate/ -v -run TestConvertRoute
```

Expected: The test that checks the `LocalOptions.Path` may need updating if any test asserts the path. The current tests only check `Type` and `Tag`, so they should still pass.

- [ ] **Step 3: Add assertions for `.srs` path in route tests**

In `generate/route_test.go`, update `TestConvertRouteWithRules` and `TestConvertRouteWithCustomRuleSets` to verify the `.srs` path.

Add to `TestConvertRouteWithRules` after the existing checks (before the closing `}`):

```go
	if opts.RuleSet[1].LocalOptions.Path != "rule-set/extension.srs" {
		t.Errorf("RuleSet[1].Path = %q, want %q", opts.RuleSet[1].LocalOptions.Path, "rule-set/extension.srs")
	}
```

Update `TestConvertRouteWithCustomRuleSets` to verify paths:

Replace the existing test body with:

```go
func TestConvertRouteWithCustomRuleSets(t *testing.T) {
	t.Parallel()

	route := &config.Route{
		Final:          "direct",
		CustomRuleSets: []string{"extension", "fastly"},
	}

	opts, err := ConvertRoute(route)
	if err != nil {
		t.Fatalf("ConvertRoute: %v", err)
	}

	localCount := 0
	for _, rs := range opts.RuleSet {
		if rs.Type == "local" {
			localCount++
		}
	}
	if localCount != 2 {
		t.Errorf("expected 2 local rule sets, got %d", localCount)
	}

	paths := map[string]bool{}
	for _, rs := range opts.RuleSet {
		if rs.Type == "local" {
			paths[rs.LocalOptions.Path] = true
		}
	}
	if !paths["rule-set/extension.srs"] {
		t.Error("missing rule-set/extension.srs path")
	}
	if !paths["rule-set/fastly.srs"] {
		t.Error("missing rule-set/fastly.srs path")
	}
}
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
go test ./generate/ -v -run TestConvertRoute
```

Expected: All route tests PASS.

- [ ] **Step 5: Run linter**

```bash
golangci-lint run --fix
```

Expected: no errors.

- [ ] **Step 6: Commit**

```bash
git add generate/route.go generate/route_test.go
git commit -m "feat(generate): use .srs extension for local rule-set paths"
```

---

## Task 4: Integrate Rule-Set Compilation into `GenerateServer`

**Files:**
- Modify: `generate/server.go:46-114`
- Modify: `generate/server_test.go`

- [ ] **Step 1: Write the failing test for rule-set compilation in generation**

Add a new test to `generate/server_test.go` (read the existing file first to see what's there, then append):

```go
func TestGenerateServerCompilesRuleSets(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	ruleSetSource := `{
  "rules": [
    {
      "domain_suffix": [".example.com"]
    }
  ]
}`
	if err := os.WriteFile(filepath.Join(dir, "extension.json"), []byte(ruleSetSource), 0o644); err != nil {
		t.Fatalf("write rule-set source: %v", err)
	}

	cfg := config.Config{
		Version: 1,
		Endpoint: "1.2.3.4",
		DNS: config.DNS{
			Final:   new("dns-local"),
			Servers: []config.DNSServer{{Type: "local", Tag: "dns-local"}},
		},
		Outbounds: []config.Outbound{
			{Type: "direct", Tag: "direct"},
		},
		Route: &config.Route{
			Final:          "direct",
			CustomRuleSets: []string{"extension"},
		},
	}

	result, err := GenerateServer(dir, cfg, GenerateConfig{})
	if err != nil {
		t.Fatalf("GenerateServer: %v", err)
	}

	srsFile := findFile(result.Files, "rule-set/extension.srs")
	if srsFile == nil {
		t.Fatal("rule-set/extension.srs not in result files")
	}
	if len(srsFile.Content) == 0 {
		t.Fatal("rule-set/extension.srs is empty")
	}
}
```

Make sure the test file imports `os` and `path/filepath` if not already imported. Also ensure the helper function `new` and `findFile` are available (they exist in the existing test files).

- [ ] **Step 2: Run test to verify it fails**

```bash
go test ./generate/ -v -run TestGenerateServerCompilesRuleSets
```

Expected: FAIL — `rule-set/extension.srs` not in result files.

- [ ] **Step 3: Update `GenerateServer` to compile rule-sets**

In `generate/server.go`, add the import for the `ruleset` package:

```go
import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"path/filepath"

	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	singjson "github.com/sagernet/sing/common/json"

	"github.com/Arsolitt/cheburbox/config"
	"github.com/Arsolitt/cheburbox/ruleset"
)
```

Add a `compileRuleSets` function and call it from `GenerateServer`. Insert the call after `resolveCertificates` and before `ConvertDNS`:

Add the function at the end of `server.go`:

```go
// compileRuleSets discovers and compiles local rule-set source files (.json → .srs).
// Only rule-sets declared in CustomRuleSets are compiled. Returns compiled .srs
// files as FileOutput entries.
func compileRuleSets(dir string, cfg *config.Config) ([]FileOutput, error) {
	if cfg.Route == nil || len(cfg.Route.CustomRuleSets) == 0 {
		return nil, nil
	}

	sources, err := ruleset.FindSourceFiles(dir, cfg.Route.CustomRuleSets)
	if err != nil {
		return nil, fmt.Errorf("discover rule-set sources: %w", err)
	}

	if len(sources) == 0 {
		return nil, nil
	}

	ruleSetDir := filepath.Join(dir, "rule-set")
	if err := os.MkdirAll(ruleSetDir, 0o755); err != nil {
		return nil, fmt.Errorf("create rule-set directory: %w", err)
	}

	files := make([]FileOutput, 0, len(sources))
	for _, src := range sources {
		content, readErr := os.ReadFile(src.Path)
		if readErr != nil {
			return nil, fmt.Errorf("read rule-set source %s: %w", src.Name, readErr)
		}

		outputPath := filepath.Join(ruleSetDir, src.Name+".srs")
		if err := ruleset.Compile(content, outputPath); err != nil {
			return nil, fmt.Errorf("compile rule-set %s: %w", src.Name, err)
		}

		compiledContent, readErr := os.ReadFile(outputPath)
		if readErr != nil {
			return nil, fmt.Errorf("read compiled rule-set %s: %w", src.Name, readErr)
		}

		relPath := filepath.Join("rule-set", src.Name+".srs")
		files = append(files, FileOutput{Path: relPath, Content: compiledContent})
	}

	return files, nil
}
```

In `GenerateServer`, add the call after `resolveCertificates`:

```go
	certFiles, err := resolveCertificates(dir, cfg, genCfg.Clean)
	if err != nil {
		return GenerateResult{}, fmt.Errorf("resolve certificates: %w", err)
	}

	ruleSetFiles, err := compileRuleSets(dir, &cfg)
	if err != nil {
		return GenerateResult{}, fmt.Errorf("compile rule-sets: %w", err)
	}
```

And update the `files` assembly to include rule-set files:

```go
	files := make([]FileOutput, 0, 1+len(certFiles)+len(ruleSetFiles))
	files = append(files, FileOutput{Path: "config.json", Content: configJSON})
	files = append(files, certFiles...)
	files = append(files, ruleSetFiles...)
```

Note: `compileRuleSets` writes to disk temporarily (the `srs.Write` function requires an `io.Writer`). This is acceptable because the `GenerateServer` function's output is a list of `FileOutput` entries that the caller writes to disk. The temporary `.srs` file is read back and included in the output. In a future refactor (Phase 5 batch write), this can use an in-memory buffer instead.

- [ ] **Step 4: Run test to verify it passes**

```bash
go test ./generate/ -v -run TestGenerateServerCompilesRuleSets
```

Expected: PASS.

- [ ] **Step 5: Run all generate tests to check for regressions**

```bash
go test ./generate/ -v
```

Expected: All tests PASS. Note that the integration test `TestIntegrationFullGeneration` references `CustomRuleSets: []string{"extension"}` but the temp dir doesn't have an `extension.json` file, so no rule-set will be compiled (the discovery function will simply not find it, returning nil — this is correct behavior).

- [ ] **Step 6: Run linter**

```bash
golangci-lint run --fix
```

Expected: no errors.

- [ ] **Step 7: Commit**

```bash
git add generate/server.go generate/server_test.go
git commit -m "feat(generate): auto-compile local rule-sets during generation"
```

---

## Task 5: Add `rule-set compile` CLI Command

**Files:**
- Modify: `cmd/cheburbox/main.go`

- [ ] **Step 1: Write the failing test for the `rule-set compile` command**

Add to `cmd/cheburbox/generate_test.go` (read the existing file first to understand patterns):

```go
func TestRuleSetCompile(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	ruleSetSource := `{
  "rules": [
    {
      "domain_suffix": [".example.com"]
    }
  ]
}`
	inputPath := filepath.Join(dir, "test.json")
	if err := os.WriteFile(inputPath, []byte(ruleSetSource), 0o644); err != nil {
		t.Fatalf("write source: %v", err)
	}

	outputPath := filepath.Join(dir, "test.srs")

	cmd := newCommand(t)
	cmd.SetArgs([]string{"rule-set", "compile", "--input", inputPath, "--output", outputPath})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}

	if _, err := os.Stat(outputPath); err != nil {
		t.Fatalf("output file not created: %v", err)
	}
}

func TestRuleSetCompileWithServer(t *testing.T) {
	t.Parallel()

	projectDir := t.TempDir()
	serverDir := filepath.Join(projectDir, "testserver")
	if err := os.MkdirAll(serverDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	cheburboxJSON := `{
  "version": 1,
  "endpoint": "1.2.3.4",
  "dns": {"servers": [{"type": "local", "tag": "dns-local"}], "final": "dns-local"},
  "outbounds": [{"type": "direct", "tag": "direct"}],
  "route": {"final": "direct", "custom_rule_sets": ["extension"]}
}`
	if err := os.WriteFile(filepath.Join(serverDir, "cheburbox.json"), []byte(cheburboxJSON), 0o644); err != nil {
		t.Fatalf("write cheburbox.json: %v", err)
	}

	ruleSetSource := `{"rules": [{"domain_keyword": ["ads"]}]}`
	if err := os.WriteFile(filepath.Join(serverDir, "extension.json"), []byte(ruleSetSource), 0o644); err != nil {
		t.Fatalf("write extension.json: %v", err)
	}

	expectedOutput := filepath.Join(serverDir, "rule-set", "extension.srs")

	cmd := newCommand(t)
	cmd.SetArgs([]string{"rule-set", "compile", "--server", "testserver", "--project", projectDir})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}

	if _, err := os.Stat(expectedOutput); err != nil {
		t.Fatalf("output file not created at %s: %v", expectedOutput, err)
	}
}
```

Check if `newCommand` helper exists in `generate_test.go`. If not, add it:

```go
func newCommand(t *testing.T) *cobra.Command {
	t.Helper()
	return NewRootCommand()
}
```

This requires exporting `NewRootCommand` from `main.go`. Alternatively, the test can construct the command the same way `main()` does. The simpler approach: test the `ruleset.Compile` function directly (already covered in Task 1) and keep the CLI test minimal.

**Simpler approach — just test the command runs:**

```go
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
```

- [ ] **Step 2: Run test to verify it fails**

```bash
go test ./cmd/cheburbox/ -v -run TestRuleSetCompile
```

Expected: FAIL — `rule-set` subcommand does not exist.

- [ ] **Step 3: Implement `rule-set compile` command**

Refactor `cmd/cheburbox/main.go` to extract the root command creation into a `NewRootCommand` function, and add the `rule-set compile` subcommand.

Replace the entire `main.go` with:

```go
// Package main is the CLI entry point for cheburbox.
package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/Arsolitt/cheburbox/config"
	"github.com/Arsolitt/cheburbox/generate"
	"github.com/Arsolitt/cheburbox/ruleset"
)

func main() {
	if err := NewRootCommand().Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

// NewRootCommand creates and returns the root cobra command with all subcommands.
func NewRootCommand() *cobra.Command {
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

	var serverName string
	var clean bool

	generateCmd := &cobra.Command{
		Use:   "generate",
		Short: "Generate sing-box configuration files for servers.",
		RunE: func(command *cobra.Command, _ []string) error {
			proj := projectRoot
			if proj == "" {
				var err error
				proj, err = os.Getwd()
				if err != nil {
					return fmt.Errorf("get working directory: %w", err)
				}
			}
			return runGenerate(command.OutOrStdout(), proj, jpath, serverName, clean)
		},
	}

	generateCmd.Flags().StringVar(&serverName, "server", "", "generate only this server")
	generateCmd.Flags().BoolVar(&clean, "clean", false, "remove undeclared users/credentials")

	rootCmd.AddCommand(generateCmd)

	ruleSetCmd := &cobra.Command{
		Use:   "rule-set",
		Short: "Manage local rule-sets.",
	}

	compileCmd := &cobra.Command{
		Use:   "compile",
		Short: "Compile local rule-set from JSON to binary .srs format.",
		RunE: func(command *cobra.Command, _ []string) error {
			return runRuleSetCompile(command.OutOrStdout(), projectRoot, jpath, serverName)
		},
	}

	compileCmd.Flags().StringVar(&serverName, "server", "", "server name (auto-compiles all rule-sets in server directory)")
	rootCmd.AddCommand(ruleSetCmd)
	ruleSetCmd.AddCommand(compileCmd)

	return rootCmd
}
```

Add the `runRuleSetCompile` function and the `--input`/`--output` flags. Since the `rule-set compile` command has two modes:

1. **With `--server`**: auto-discover and compile all rule-sets in the server directory.
2. **With `--input` and `--output`**: compile a single file.

Add these flags to `compileCmd`:

```go
	var compileInput string
	var compileOutput string
	var compileServer string

	compileCmd := &cobra.Command{
		Use:   "compile",
		Short: "Compile local rule-set from JSON to binary .srs format.",
		RunE: func(command *cobra.Command, _ []string) error {
			return runRuleSetCompile(command.OutOrStdout(), projectRoot, compileServer, compileInput, compileOutput)
		},
	}

	compileCmd.Flags().StringVar(&compileServer, "server", "", "server name (auto-compiles all rule-sets in server directory)")
	compileCmd.Flags().StringVar(&compileInput, "input", "", "input JSON rule-set file path")
	compileCmd.Flags().StringVar(&compileOutput, "output", "", "output .srs file path")
```

And the run function:

```go
func runRuleSetCompile(
	w io.Writer,
	projectRoot string,
	serverName string,
	input string,
	output string,
) error {
	if serverName != "" {
		return runRuleSetCompileServer(w, projectRoot, serverName)
	}

	if input == "" || output == "" {
		return fmt.Errorf("--input and --output are required when --server is not specified")
	}

	return runRuleSetCompileSingle(w, input, output)
}

func runRuleSetCompileSingle(w io.Writer, input string, output string) error {
	content, err := os.ReadFile(input)
	if err != nil {
		return fmt.Errorf("read input: %w", err)
	}

	if err := ruleset.Compile(content, output); err != nil {
		return fmt.Errorf("compile: %w", err)
	}

	fmt.Fprintf(w, "Compiled %s -> %s\n", input, output)

	return nil
}

func runRuleSetCompileServer(w io.Writer, projectRoot string, serverName string) error {
	proj := projectRoot
	if proj == "" {
		var err error
		proj, err = os.Getwd()
		if err != nil {
			return fmt.Errorf("get working directory: %w", err)
		}
	}

	dir := filepath.Join(proj, serverName)
	jpathAbs := resolveJPath(proj, "")

	cfg, err := config.LoadServerWithJsonnet(dir, jpathAbs)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	if cfg.Route == nil || len(cfg.Route.CustomRuleSets) == 0 {
		fmt.Fprintln(w, "no custom rule-sets defined for server")
		return nil
	}

	sources, err := ruleset.FindSourceFiles(dir, cfg.Route.CustomRuleSets)
	if err != nil {
		return fmt.Errorf("discover rule-set sources: %w", err)
	}

	if len(sources) == 0 {
		fmt.Fprintln(w, "no rule-set source files found in server directory")
		return nil
	}

	ruleSetDir := filepath.Join(dir, "rule-set")
	if err := os.MkdirAll(ruleSetDir, 0o755); err != nil {
		return fmt.Errorf("create rule-set directory: %w", err)
	}

	for _, src := range sources {
		content, err := os.ReadFile(src.Path)
		if err != nil {
			return fmt.Errorf("read %s: %w", src.Name, err)
		}

		outputPath := filepath.Join(ruleSetDir, src.Name+".srs")
		if err := ruleset.Compile(content, outputPath); err != nil {
			return fmt.Errorf("compile %s: %w", src.Name, err)
		}

		fmt.Fprintf(w, "Compiled %s -> %s\n", src.Name, outputPath)
	}

	return nil
}
```

- [ ] **Step 4: Run test to verify it passes**

```bash
go test ./cmd/cheburbox/ -v -run TestRuleSetCompile
```

Expected: PASS.

- [ ] **Step 5: Run all tests**

```bash
go test ./... -v
```

Expected: All tests PASS.

- [ ] **Step 6: Run linter**

```bash
golangci-lint run --fix
```

Expected: no errors.

- [ ] **Step 7: Build the binary and test CLI manually**

```bash
go build -o build/cheburbox ./cmd/cheburbox/
./build/cheburbox rule-set compile --help
```

Expected: Shows help for the `rule-set compile` command with `--server`, `--input`, `--output` flags.

- [ ] **Step 8: Commit**

```bash
git add cmd/cheburbox/main.go cmd/cheburbox/generate_test.go
git commit -m "feat(cli): add rule-set compile command"
```

---

## Task 6: End-to-End Verification

**Files:** None (verification only)

- [ ] **Step 1: Run full test suite**

```bash
go test ./... -v -count=1
```

Expected: All tests PASS.

- [ ] **Step 2: Run linter**

```bash
golangci-lint run --fix
```

Expected: no errors.

- [ ] **Step 3: Build and verify binary**

```bash
go build -o build/cheburbox ./cmd/cheburbox/
./build/cheburbox --help
./build/cheburbox rule-set compile --help
```

Expected: Both help outputs display correctly.

---

## Self-Review Checklist

1. **Spec coverage:**
   - Wrap sing-box `common/srs` for `.json` → `.srs` compilation → Task 1
   - Auto-compile all `*.json` rule-set source files in server directory during `generate` → Task 4
   - Standalone `rule-set compile` command with `--server`, `--input`, `--output` flags → Task 5
   - Tests with sample rule-set JSON → Tasks 1, 2, 4, 5

2. **Placeholder scan:**
   - No TBDs, TODOs, or vague instructions found.
   - All code blocks contain actual implementation code.

3. **Type consistency:**
   - `ruleset.SourceFile` used consistently in Tasks 2, 4, 5.
   - `ruleset.Compile(input []byte, outputPath string)` signature consistent across all tasks.
   - `FileOutput` type from `generate` package used consistently.
   - `.srs` extension used consistently in route conversion and CLI output paths.
