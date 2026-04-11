package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/google/go-jsonnet"
)

const configJSON = "cheburbox.json"

const configJsonnet = ".cheburbox.jsonnet"

// Discover finds all direct child directories under projectRoot that
// contain cheburbox.json or .cheburbox.jsonnet. Returns sorted directory names.
func Discover(projectRoot string) ([]string, error) {
	entries, err := os.ReadDir(projectRoot)
	if err != nil {
		return nil, fmt.Errorf("read project root %s: %w", projectRoot, err)
	}

	var servers []string

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		dirPath := filepath.Join(projectRoot, entry.Name())
		if hasConfig(dirPath) {
			servers = append(servers, entry.Name())
		}
	}

	sort.Strings(servers)
	return servers, nil
}

func hasConfig(dir string) bool {
	_, errJSON := os.Stat(filepath.Join(dir, configJSON))
	_, errJsonnet := os.Stat(filepath.Join(dir, configJsonnet))
	return errJSON == nil || errJsonnet == nil
}

// loadServer reads and parses the cheburbox.json from the given directory.
// Returns an error if no config file is found or parsing fails.
func loadServer(dir string) (Config, error) {
	jsonPath := filepath.Join(dir, configJSON)

	if _, err := os.Stat(jsonPath); err != nil {
		return Config{}, fmt.Errorf("no config file found in %s", dir)
	}

	return loadFromJSON(jsonPath)
}

func loadFromJSON(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read %s: %w", path, err)
	}

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return Config{}, fmt.Errorf("parse %s: %w", path, err)
	}

	if cfg.Version == 0 {
		return Config{}, fmt.Errorf("%s: missing or zero version field", path)
	}

	return cfg, nil
}

// createJsonnetVM creates a jsonnet VM with the given jpath (library search path).
func createJsonnetVM(jpath string) *jsonnet.VM {
	vm := jsonnet.MakeVM()
	if jpath != "" {
		vm.Importer(&jsonnet.FileImporter{
			JPaths: []string{jpath},
		})
	}
	return vm
}

// LoadServerWithJsonnet reads, evaluates (if .cheburbox.jsonnet), and parses
// the config from dir. If jpath is non-empty, it is used as the jsonnet library
// search path. .cheburbox.jsonnet takes precedence over cheburbox.json.
func LoadServerWithJsonnet(dir string, jpath string) (Config, error) {
	jsonnetPath := filepath.Join(dir, configJsonnet)
	jsonPath := filepath.Join(dir, configJSON)

	_, errJsonnet := os.Stat(jsonnetPath)
	_, errJSON := os.Stat(jsonPath)

	switch {
	case errJsonnet == nil:
		vm := createJsonnetVM(jpath)
		output, err := vm.EvaluateFile(jsonnetPath)
		if err != nil {
			return Config{}, fmt.Errorf("evaluate jsonnet %s: %w", jsonnetPath, err)
		}

		var cfg Config
		if err := json.Unmarshal([]byte(output), &cfg); err != nil {
			return Config{}, fmt.Errorf("parse jsonnet output from %s: %w", jsonnetPath, err)
		}

		if cfg.Version == 0 {
			return Config{}, fmt.Errorf("%s: missing or zero version field", jsonnetPath)
		}

		return cfg, nil
	case errJSON == nil:
		return loadFromJSON(jsonPath)
	default:
		return Config{}, fmt.Errorf("no config file found in %s", dir)
	}
}

// Validate checks a Config for required fields and consistency rules.
func Validate(cfg Config) error {
	if cfg.Version != CurrentSchemaVersion {
		return fmt.Errorf("unsupported version %d (want %d)", cfg.Version, CurrentSchemaVersion)
	}

	if len(cfg.DNS.Servers) == 0 {
		return errors.New("dns section is required: at least one dns server must be defined")
	}

	if len(cfg.Inbounds) > 0 && cfg.Endpoint == "" {
		return errors.New("endpoint is required when inbounds are defined")
	}

	for _, in := range cfg.Inbounds {
		if in.ListenPort < 0 || in.ListenPort > 65535 {
			return fmt.Errorf(
				"inbound %q: listen_port %d is out of range (0-65535)",
				in.Tag,
				in.ListenPort,
			)
		}
	}

	return nil
}
