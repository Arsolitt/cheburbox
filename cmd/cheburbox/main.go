// Package main is the CLI entry point for cheburbox.
package main

import (
	"errors"
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

// NewRootCommand creates and returns the root cobra command for cheburbox.
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

	compileCmd.Flags().
		StringVar(&compileServer, "server", "", "server name (auto-compiles all rule-sets in server directory)")
	compileCmd.Flags().StringVar(&compileInput, "input", "", "input JSON rule-set file path")
	compileCmd.Flags().StringVar(&compileOutput, "output", "", "output .srs file path")

	ruleSetCmd := &cobra.Command{
		Use:   "rule-set",
		Short: "Manage local rule-sets.",
	}

	ruleSetCmd.AddCommand(compileCmd)
	rootCmd.AddCommand(ruleSetCmd)

	return rootCmd
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

func runRuleSetCompile(w io.Writer, projectRoot string, serverName string, input string, output string) error {
	if serverName != "" {
		return runRuleSetCompileServer(w, projectRoot, serverName)
	}

	if input == "" || output == "" {
		return errors.New("--input and --output are required when --server is not specified")
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
	if err := os.MkdirAll(ruleSetDir, 0o750); err != nil {
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
