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
// <name>.json in the directory. Files that are cheburbox.json, config.json,
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
