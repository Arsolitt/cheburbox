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
