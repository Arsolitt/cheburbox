// Package main is the CLI entry point for cheburbox.
package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	cheburcmd "github.com/Arsolitt/cheburbox/internal/cmd"
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
			return cheburcmd.RunGenerate(command.OutOrStdout(), proj, jpath, serverName)
		},
	}

	generateCmd.Flags().StringVar(&serverName, "server", "", "generate only this server")

	rootCmd.AddCommand(generateCmd)

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
