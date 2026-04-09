// Package validate provides configuration validation in two phases.
//
// Phase 1 validates cheburbox.json configs for each server independently
// (intra-server checks such as hysteria2 server_name collisions).
//
// Phase 2 validates generated sing-box configs across all servers
// (cross-server checks).
package validate

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/include"
	singjson "github.com/sagernet/sing/common/json"

	"github.com/Arsolitt/cheburbox/config"
	"github.com/Arsolitt/cheburbox/generate"
)

// ServerResult holds validation results for a single server.
type ServerResult struct {
	Server   string
	Errors   []error
	Warnings []string
}

// Failed returns true if the server has validation errors.
func (r *ServerResult) Failed() bool {
	return len(r.Errors) > 0
}

// ValidateAll discovers all servers in the project and runs both
// validation phases on them.
//
//nolint:revive // stutter is intentional for API clarity.
func ValidateAll(projectRoot string, jpath string) ([]ServerResult, error) {
	servers, err := config.Discover(projectRoot)
	if err != nil {
		return nil, fmt.Errorf("discover servers: %w", err)
	}

	if len(servers) == 0 {
		return nil, nil
	}

	configs, err := loadConfigs(servers, projectRoot, jpath)
	if err != nil {
		return nil, err
	}

	return runPhase1AndPhase2(configs, projectRoot)
}

// ValidateServers validates the specified server and its transitive
// dependencies.
//
//nolint:revive // stutter is intentional for API clarity.
func ValidateServers(projectRoot string, jpath string, serverName string) ([]ServerResult, error) {
	allServers, err := config.Discover(projectRoot)
	if err != nil {
		return nil, fmt.Errorf("discover servers: %w", err)
	}

	allConfigs, err := loadConfigs(allServers, projectRoot, jpath)
	if err != nil {
		return nil, err
	}

	graph, err := generate.BuildGraph(allConfigs)
	if err != nil {
		return nil, fmt.Errorf("build dependency graph: %w", err)
	}

	deps, err := graph.TransitiveDependencies(serverName)
	if err != nil {
		return nil, fmt.Errorf("resolve dependencies for %s: %w", serverName, err)
	}

	configs := make(map[string]config.Config, len(deps))
	for _, dep := range deps {
		configs[dep] = allConfigs[dep]
	}

	return runPhase1AndPhase2(configs, projectRoot)
}

func runPhase1AndPhase2(configs map[string]config.Config, projectRoot string) ([]ServerResult, error) {
	phase1Results := runPhase1(configs)

	hasGlobalErr := false
	for _, r := range phase1Results {
		if r.Server == "(global)" {
			hasGlobalErr = true

			break
		}
	}

	if hasGlobalErr {
		return phase1Results, nil
	}

	runPhase2(phase1Results, projectRoot)

	sort.Slice(phase1Results, func(i, j int) bool {
		return phase1Results[i].Server < phase1Results[j].Server
	})

	return phase1Results, nil
}

func runPhase1(configs map[string]config.Config) []ServerResult {
	graph, err := generate.BuildGraph(configs)
	if err != nil {
		return []ServerResult{
			{
				Server: "(global)",
				Errors: []error{err},
			},
		}
	}

	_ = graph

	crossServerErrs := checkOutboundInboundRefs(configs)

	sortedServers := make([]string, 0, len(configs))
	for name := range configs {
		sortedServers = append(sortedServers, name)
	}
	sort.Strings(sortedServers)

	results := make([]ServerResult, 0, len(sortedServers))

	for _, name := range sortedServers {
		cfg := configs[name]
		var errs []error

		if validateErr := config.Validate(cfg); validateErr != nil {
			errs = append(errs, validateErr)
		}

		errs = append(errs, checkHysteria2ServerNameCollision(name, cfg)...)
		errs = append(errs, checkOutboundGroupRefs(name, cfg)...)

		for _, ce := range crossServerErrs {
			if strings.Contains(ce.Error(), fmt.Sprintf("server %q ", name)) {
				errs = append(errs, ce)
			}
		}
		// The trailing space in "server %q " is critical: it matches the source server
		// (which is followed by a space before "outbound"), not the target server
		// (which is preceded by ", " in "on server %q,").

		results = append(results, ServerResult{
			Server: name,
			Errors: errs,
		})
	}

	return results
}

func runPhase2(results []ServerResult, projectRoot string) {
	for i := range results {
		if results[i].Failed() {
			continue
		}

		configPath := filepath.Join(projectRoot, results[i].Server, "config.json")
		if _, err := os.Stat(configPath); err != nil {
			results[i].Warnings = append(
				results[i].Warnings,
				fmt.Sprintf("skipped sing-box check: %s/config.json not found", results[i].Server),
			)

			continue
		}

		if err := singBoxCheck(configPath); err != nil {
			results[i].Errors = append(results[i].Errors, err)
		}
	}
}

func loadConfigs(
	servers []string,
	projectRoot string,
	jpath string,
) (map[string]config.Config, error) {
	configs := make(map[string]config.Config, len(servers))

	for _, name := range servers {
		dir := filepath.Join(projectRoot, name)
		cfg, err := config.LoadServerWithJsonnet(dir, jpath)
		if err != nil {
			return nil, fmt.Errorf("load config for %s: %w", name, err)
		}
		configs[name] = cfg
	}

	return configs, nil
}

// checkHysteria2ServerNameCollision detects hysteria2 inbounds that share
// the same tls.server_name, which would cause cert file conflicts.
func checkHysteria2ServerNameCollision(server string, cfg config.Config) []error {
	seen := make(map[string]string) // server_name -> first tag
	var errs []error

	for _, in := range cfg.Inbounds {
		if in.Type != "hysteria2" {
			continue
		}
		if in.TLS == nil || in.TLS.ServerName == "" {
			continue
		}
		if prev, ok := seen[in.TLS.ServerName]; ok {
			errs = append(errs, fmt.Errorf(
				"server %q: hysteria2 inbounds %q and %q share the same tls.server_name %q (would conflict on cert files)",
				server,
				prev,
				in.Tag,
				in.TLS.ServerName,
			))
		} else {
			seen[in.TLS.ServerName] = in.Tag
		}
	}

	return errs
}

// checkOutboundInboundRefs validates that outbound inbound references point to
// existing inbound tags on the target server.
func checkOutboundInboundRefs(configs map[string]config.Config) []error {
	serverTags := make(map[string]map[string]bool) // server -> set of inbound tags
	for name, cfg := range configs {
		tags := make(map[string]bool)
		for _, in := range cfg.Inbounds {
			tags[in.Tag] = true
		}
		serverTags[name] = tags
	}

	var errs []error

	for name, cfg := range configs {
		for _, out := range cfg.Outbounds {
			if out.Server == "" || out.Inbound == "" {
				continue
			}
			tags, ok := serverTags[out.Server]
			if !ok {
				continue
			}
			if !tags[out.Inbound] {
				errs = append(errs, fmt.Errorf(
					"server %q outbound %q references inbound %q on server %q, but no such inbound exists",
					name,
					out.Tag,
					out.Inbound,
					out.Server,
				))
			}
		}
	}

	return errs
}

// singBoxCheck reads a config.json file, parses it with registry-aware
// unmarshaling, creates a sing-box instance, and immediately closes it.
// This replicates the behavior of `sing-box check`.
func singBoxCheck(configPath string) error {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("read config.json: %w", err)
	}

	ctx := include.Context(context.Background())

	opts, unmarshalErr := singjson.UnmarshalExtendedContext[box.Options](ctx, data)
	if unmarshalErr != nil {
		return fmt.Errorf("parse config.json: %w", unmarshalErr)
	}

	opts.Context = ctx

	instance, err := box.New(opts)
	if err != nil {
		return fmt.Errorf("sing-box check: %w", err)
	}

	instance.Close()

	return nil
}

// findGenerateFile finds a FileOutput by path. Returns nil if not found.
func findGenerateFile(files []generate.FileOutput, path string) *generate.FileOutput {
	for i := range files {
		if files[i].Path == path {
			return &files[i]
		}
	}
	return nil
}

// checkOutboundGroupRefs validates that urltest and selector outbound groups
// reference only outbound tags that exist in the same server.
func checkOutboundGroupRefs(server string, cfg config.Config) []error {
	validTags := make(map[string]bool)
	for _, out := range cfg.Outbounds {
		validTags[out.Tag] = true
	}

	var errs []error

	for _, out := range cfg.Outbounds {
		if out.Type != "urltest" && out.Type != "selector" {
			continue
		}
		if len(out.Outbounds) == 0 {
			continue
		}
		for _, ref := range out.Outbounds {
			if !validTags[ref] {
				errs = append(errs, fmt.Errorf(
					"server %q %s outbound %q references unknown outbound %q",
					server,
					out.Type,
					out.Tag,
					ref,
				))
			}
		}
	}

	return errs
}
