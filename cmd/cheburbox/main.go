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

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func runGenerate(w io.Writer, projectRoot string, jpath string, serverName string, clean bool) error {
	if serverName != "" {
		return runGenerateServer(w, projectRoot, jpath, serverName, clean)
	}

	return runGenerateAll(w, projectRoot, jpath, clean)
}

func runGenerateAll(w io.Writer, projectRoot string, jpath string, clean bool) error {
	servers, err := config.Discover(projectRoot)
	if err != nil {
		return fmt.Errorf("discover servers: %w", err)
	}

	if len(servers) == 0 {
		fmt.Fprintln(w, "no servers found in project")
		return nil
	}

	for _, name := range servers {
		if err := generateServer(w, projectRoot, jpath, name, clean); err != nil {
			return fmt.Errorf("server %s: %w", name, err)
		}
	}

	return nil
}

func runGenerateServer(w io.Writer, projectRoot string, jpath string, serverName string, clean bool) error {
	dir := filepath.Join(projectRoot, serverName)
	if _, err := os.Stat(dir); err != nil {
		return fmt.Errorf("server %s: %w", serverName, err)
	}

	return generateServer(w, projectRoot, jpath, serverName, clean)
}

func generateServer(w io.Writer, projectRoot string, jpath string, name string, clean bool) error {
	dir := filepath.Join(projectRoot, name)
	jpathAbs := resolveJPath(projectRoot, jpath)

	cfg, err := config.LoadServerWithJsonnet(dir, jpathAbs)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	if err := config.Validate(cfg); err != nil {
		return fmt.Errorf("validate: %w", err)
	}

	genCfg := generate.GenerateConfig{Clean: clean}
	result, err := generate.GenerateServer(dir, cfg, genCfg)
	if err != nil {
		return fmt.Errorf("generate: %w", err)
	}

	for _, f := range result.Files {
		path := filepath.Join(dir, f.Path)
		//nolint:gosec // config files must be readable by the sing-box process.
		if err := os.WriteFile(path, f.Content, 0o644); err != nil {
			return fmt.Errorf("write %s: %w", f.Path, err)
		}
	}

	fmt.Fprintf(w, "Generated %d files for server %s\n", len(result.Files), name)

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
