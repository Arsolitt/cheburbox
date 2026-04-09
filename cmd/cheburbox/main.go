package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/Arsolitt/cheburbox/config"
	"github.com/Arsolitt/cheburbox/generate"
	"github.com/Arsolitt/cheburbox/ruleset"
	"github.com/Arsolitt/cheburbox/validate"
)

func main() {
	if err := NewRootCommand().Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

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
	var dryRun bool

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
			return runGenerate(command.OutOrStdout(), proj, jpath, serverName, clean, dryRun)
		},
	}

	generateCmd.Flags().StringVar(&serverName, "server", "", "generate only this server and its dependencies")
	generateCmd.Flags().BoolVar(&clean, "clean", false, "remove undeclared users/credentials")
	generateCmd.Flags().BoolVar(&dryRun, "dry-run", false, "output JSON to stdout without writing files")

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

	return rootCmd
}

func runGenerate(
	w io.Writer,
	projectRoot string,
	jpath string,
	serverName string,
	clean bool,
	dryRun bool,
) error {
	genCfg := generate.GenerateConfig{Clean: clean}
	jpathAbs := resolveJPath(projectRoot, jpath)

	var results []generate.GenerateResult
	var err error

	if serverName != "" {
		results, err = generate.GenerateServers(projectRoot, jpathAbs, serverName, genCfg)
	} else {
		results, err = generate.GenerateAll(projectRoot, jpathAbs, genCfg)
	}

	if err != nil {
		return err
	}

	if len(results) == 0 {
		fmt.Fprintln(w, "no servers found in project")
		return nil
	}

	if dryRun {
		return writeDryRunOutput(w, results)
	}

	return writeResults(w, projectRoot, results)
}

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
		return errors.New("validation failed")
	}

	return nil
}

func writeDryRunOutput(w io.Writer, results []generate.GenerateResult) error {
	type fileEntry struct {
		Path    string `json:"path"`
		Content string `json:"content"`
	}

	type serverEntry struct {
		Server string      `json:"server"`
		Files  []fileEntry `json:"files"`
	}

	output := make([]serverEntry, 0, len(results))
	for _, result := range results {
		entry := serverEntry{
			Server: result.Server,
			Files:  make([]fileEntry, 0, len(result.Files)),
		}

		for _, f := range result.Files {
			content := base64.StdEncoding.EncodeToString(f.Content)
			entry.Files = append(entry.Files, fileEntry{
				Path:    f.Path,
				Content: content,
			})
		}

		output = append(output, entry)
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(output); err != nil {
		return fmt.Errorf("encode dry-run output: %w", err)
	}

	return nil
}

func writeResults(w io.Writer, projectRoot string, results []generate.GenerateResult) error {
	for _, result := range results {
		dir := filepath.Join(projectRoot, result.Server)

		for _, f := range result.Files {
			path := filepath.Join(dir, f.Path)
			if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
				return fmt.Errorf("create directory for %s: %w", f.Path, err)
			}
			//nolint:gosec // config files must be readable by the sing-box process.
			if err := os.WriteFile(path, f.Content, 0o644); err != nil {
				return fmt.Errorf("write %s: %w", f.Path, err)
			}
		}

		fmt.Fprintf(w, "Generated %d files for server %s\n", len(result.Files), result.Server)
	}

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

func resolveJPath(projectRoot string, jpath string) string {
	if jpath == "" {
		return ""
	}
	if filepath.IsAbs(jpath) {
		return jpath
	}
	return filepath.Join(projectRoot, jpath)
}
