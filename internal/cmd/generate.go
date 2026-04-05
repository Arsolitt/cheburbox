// Package cmd implements cheburbox CLI subcommands.
package cmd

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/Arsolitt/cheburbox/internal/config"
)

// RunGenerate executes the generate command logic.
// projectRoot is the project root directory.
// jpath is the jsonnet library path (may be empty).
// serverName is the specific server to generate (empty means all).
// Output is written to w.
func RunGenerate(w io.Writer, projectRoot string, jpath string, serverName string) error {
	if serverName != "" {
		return runGenerateServer(w, projectRoot, jpath, serverName)
	}

	return runGenerateAll(w, projectRoot, jpath)
}

func runGenerateAll(w io.Writer, projectRoot string, jpath string) error {
	servers, err := config.Discover(projectRoot)
	if err != nil {
		return fmt.Errorf("discover servers: %w", err)
	}

	if len(servers) == 0 {
		fmt.Fprintln(w, "no servers found in project")
		return nil
	}

	for _, name := range servers {
		if err := loadAndPrint(w, projectRoot, jpath, name); err != nil {
			return fmt.Errorf("server %s: %w", name, err)
		}
	}

	return nil
}

func runGenerateServer(w io.Writer, projectRoot string, jpath string, serverName string) error {
	dir := filepath.Join(projectRoot, serverName)
	if _, err := os.Stat(dir); err != nil {
		return fmt.Errorf("server %s: %w", serverName, err)
	}

	return loadAndPrint(w, projectRoot, jpath, serverName)
}

func loadAndPrint(w io.Writer, projectRoot string, jpath string, name string) error {
	dir := filepath.Join(projectRoot, name)
	jpathAbs := resolveJPath(projectRoot, jpath)

	cfg, err := config.LoadServerWithJsonnet(dir, jpathAbs)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	if err := config.Validate(cfg); err != nil {
		return fmt.Errorf("validate: %w", err)
	}

	fmt.Fprintf(w, "Server: %s\n", name)
	fmt.Fprintf(w, "  Version:  %d\n", cfg.Version)
	fmt.Fprintf(w, "  Endpoint: %s\n", cfg.Endpoint)
	fmt.Fprintf(w, "  Inbounds: %d\n", len(cfg.Inbounds))
	fmt.Fprintf(w, "  Outbounds: %d\n", len(cfg.Outbounds))
	fmt.Fprintf(w, "  DNS servers: %d\n", len(cfg.DNS.Servers))

	return nil
}

// resolveJPath returns an absolute jpath. If jpath is relative, it is resolved
// relative to projectRoot. If jpath is empty, returns empty.
func resolveJPath(projectRoot string, jpath string) string {
	if jpath == "" {
		return ""
	}
	if filepath.IsAbs(jpath) {
		return jpath
	}
	return filepath.Join(projectRoot, jpath)
}
