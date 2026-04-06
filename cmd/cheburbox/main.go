// Package main is the CLI entry point for cheburbox.
package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/Arsolitt/cheburbox/config"
)

func main() {
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

	generateCmd := &cobra.Command{
		Use:   "generate",
		Short: "Load and validate server configurations.",
		RunE: func(command *cobra.Command, _ []string) error {
			proj := projectRoot
			if proj == "" {
				var err error
				proj, err = os.Getwd()
				if err != nil {
					return fmt.Errorf("get working directory: %w", err)
				}
			}
			return runGenerate(command.OutOrStdout(), proj, jpath, serverName)
		},
	}

	generateCmd.Flags().StringVar(&serverName, "server", "", "generate only this server")

	rootCmd.AddCommand(generateCmd)

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func runGenerate(w io.Writer, projectRoot string, jpath string, serverName string) error {
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
