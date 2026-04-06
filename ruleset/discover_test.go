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
