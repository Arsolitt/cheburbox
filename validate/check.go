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
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Arsolitt/amnezigo"
	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/include"
	singjson "github.com/sagernet/sing/common/json"

	"github.com/Arsolitt/cheburbox/config"
	"github.com/Arsolitt/cheburbox/generate"
)

// serverGlobal marks a ServerResult that reports a project-wide error shared
// across servers, such as an unresolvable dependency-graph cycle.
const serverGlobal = "(global)"

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
		if r.Server == serverGlobal {
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
	_, err := generate.BuildGraph(configs)
	if err != nil {
		return []ServerResult{
			{
				Server: serverGlobal,
				Errors: []error{err},
			},
		}
	}

	crossServerErrs := checkOutboundInboundRefs(configs)
	amneziaWGCollisionErrs := checkAmneziaWGAllowedIPsCollision(configs)

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
		errs = append(errs, checkAmneziaWGInbounds(name, cfg)...)
		errs = append(errs, checkAmneziaWGOutbounds(name, cfg)...)
		errs = append(errs, checkOutboundGroupRefs(name, cfg)...)
		errs = append(errs, checkFailoverOutbounds(name, cfg)...)
		errs = append(errs, crossServerErrs[name]...)
		errs = append(errs, amneziaWGCollisionErrs[name]...)

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
		if in.Type != generate.TypeHysteria2 {
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
// existing inbound tags on the target server. Returns a map from server name
// to the list of errors attributed to that server.
func checkOutboundInboundRefs(configs map[string]config.Config) map[string][]error {
	serverTags := make(map[string]map[string]bool) // server -> set of inbound tags
	for name, cfg := range configs {
		tags := make(map[string]bool)
		for _, in := range cfg.Inbounds {
			tags[in.Tag] = true
		}
		serverTags[name] = tags
	}

	result := make(map[string][]error)

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
				result[name] = append(result[name], fmt.Errorf(
					"outbound %q references inbound %q on server %q, but no such inbound exists",
					out.Tag,
					out.Inbound,
					out.Server,
				))
			}
		}
	}

	return result
}

// singBoxCheck reads a config.json file, parses it with registry-aware
// unmarshaling, creates a sing-box instance, and immediately closes it.
// This replicates the behavior of `sing-box check`.
func singBoxCheck(configPath string) error {
	configDir := filepath.Dir(configPath)

	data, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("read config.json: %w", err)
	}

	oldWd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("get working directory: %w", err)
	}

	if err := os.Chdir(configDir); err != nil {
		return fmt.Errorf("change to config directory: %w", err)
	}

	defer func() {
		_ = os.Chdir(oldWd)
	}()

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

	_ = instance.Close()

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

// checkOutboundGroupRefs validates that urltest, selector, fallback, and failover
// outbound groups reference only outbound tags that exist in the same server.
func checkOutboundGroupRefs(server string, cfg config.Config) []error {
	validTags := make(map[string]bool)
	for _, out := range cfg.Outbounds {
		validTags[out.Tag] = true
	}

	var errs []error

	for _, out := range cfg.Outbounds {
		if out.Type != generate.TypeURLTest && out.Type != generate.TypeSelector &&
			out.Type != generate.TypeFallback && out.Type != generate.TypeFailover {
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

// checkFailoverOutbounds validates failover-specific constraints: strategy must
// be empty, "sequential", or "cycle"; and a failover outbound must not reference
// another failover outbound (the two-pass builder cannot resolve nested failover).
func checkFailoverOutbounds(server string, cfg config.Config) []error {
	failoverTags := make(map[string]bool)
	for _, out := range cfg.Outbounds {
		if out.Type == generate.TypeFailover {
			failoverTags[out.Tag] = true
		}
	}

	var errs []error
	for _, out := range cfg.Outbounds {
		if out.Type != generate.TypeFailover {
			continue
		}
		switch out.Strategy {
		case "", generate.FailoverStrategySequential, generate.FailoverStrategyCycle:
		default:
			errs = append(errs, fmt.Errorf(
				"server %q failover outbound %q: invalid strategy %q (must be sequential or cycle)",
				server, out.Tag, out.Strategy,
			))
		}
		for _, ref := range out.Outbounds {
			if failoverTags[ref] {
				errs = append(errs, fmt.Errorf(
					"server %q failover outbound %q: cannot reference another failover outbound %q",
					server, out.Tag, ref,
				))
			}
		}
	}
	return errs
}

// amneziaProtocol* constants are the transport obfuscation protocols accepted
// by AmneziaConfig.Protocol. amnezigo's protocol constants are unexported, so
// these mirror them by value.
const (
	amneziaProtocolQUIC   = "quic"
	amneziaProtocolDNS    = "dns"
	amneziaProtocolDTLS   = "dtls"
	amneziaProtocolSTUN   = "stun"
	amneziaProtocolSIP    = "sip"
	amneziaProtocolRTP    = "rtp"
	amneziaProtocolRandom = "random"
)

// allowedAmneziaWGProtocols is the set of transport obfuscation protocols
// accepted by AmneziaConfig.Protocol.
var allowedAmneziaWGProtocols = map[string]bool{
	amneziaProtocolQUIC:   true,
	amneziaProtocolDNS:    true,
	amneziaProtocolDTLS:   true,
	amneziaProtocolSTUN:   true,
	amneziaProtocolSIP:    true,
	amneziaProtocolRTP:    true,
	amneziaProtocolRandom: true,
}

// allowedAmneziaWGPresets is the set of preset names accepted by
// AmneziaConfig.Preset. Built from amnezigo.ListPresets() so new presets are
// accepted automatically after a `go get` bump.
var allowedAmneziaWGPresets = func() map[string]bool {
	m := make(map[string]bool, len(amnezigo.ListPresets()))
	for _, p := range amnezigo.ListPresets() {
		m[p.Name] = true
	}
	return m
}()

// validateSingleCIDRAddress checks that addrs contains exactly one entry and that it
// parses as a valid CIDR prefix. role qualifies the element kind in error messages
// (e.g. "amneziawg inbound" or "amneziawg outbound").
func validateSingleCIDRAddress(role, server, tag string, addrs []string) error {
	if len(addrs) != 1 {
		return fmt.Errorf(
			"server %q: %s %q requires exactly one address CIDR, got %d",
			server,
			role,
			tag,
			len(addrs),
		)
	}

	if _, err := netip.ParsePrefix(addrs[0]); err != nil {
		return fmt.Errorf(
			"server %q: %s %q has invalid address CIDR %q: %w",
			server,
			role,
			tag,
			addrs[0],
			err,
		)
	}

	return nil
}

// checkAmneziaWGInbounds validates Phase-1 intra-server rules for amneziawg
// inbounds: a non-zero listen_port, exactly one CIDR address, and (when set) an
// amnezia protocol drawn from the allowed set.
func checkAmneziaWGInbounds(server string, cfg config.Config) []error {
	var errs []error

	for _, in := range cfg.Inbounds {
		if in.Type != generate.TypeAmneziaWG {
			continue
		}

		if in.ListenPort == 0 {
			errs = append(errs, fmt.Errorf(
				"server %q: amneziawg inbound %q requires a non-zero listen_port",
				server,
				in.Tag,
			))
		}

		if err := validateSingleCIDRAddress("amneziawg inbound", server, in.Tag, in.Address); err != nil {
			errs = append(errs, err)
		}

		if in.Amnezia != nil && in.Amnezia.Protocol != "" && !allowedAmneziaWGProtocols[in.Amnezia.Protocol] {
			errs = append(errs, fmt.Errorf(
				"server %q: amneziawg inbound %q has invalid amnezia protocol %q (want one of quic, dns, dtls, stun, sip, rtp, random)",
				server,
				in.Tag,
				in.Amnezia.Protocol,
			))
		}

		if in.Amnezia != nil && in.Amnezia.Preset != "" && !allowedAmneziaWGPresets[in.Amnezia.Preset] {
			errs = append(errs, fmt.Errorf(
				"server %q: amneziawg inbound %q has unknown amnezia preset %q",
				server,
				in.Tag,
				in.Amnezia.Preset,
			))
		}
	}

	return errs
}

// checkAmneziaWGOutbounds validates Phase-1 intra-server rules for amneziawg
// outbounds: a target server, a target inbound tag, and exactly one CIDR address.
func checkAmneziaWGOutbounds(server string, cfg config.Config) []error {
	var errs []error

	for _, out := range cfg.Outbounds {
		if out.Type != generate.TypeAmneziaWG {
			continue
		}

		if out.Server == "" {
			errs = append(errs, fmt.Errorf(
				"server %q: amneziawg outbound %q requires a target server",
				server,
				out.Tag,
			))
		}

		if out.Inbound == "" {
			errs = append(errs, fmt.Errorf(
				"server %q: amneziawg outbound %q requires a target inbound",
				server,
				out.Tag,
			))
		}

		if err := validateSingleCIDRAddress("amneziawg outbound", server, out.Tag, out.Address); err != nil {
			errs = append(errs, err)
		}
	}

	return errs
}

// checkAmneziaWGAllowedIPsCollision detects amneziawg outbounds across the
// whole project whose address CIDR collides for the same target (server,
// inbound). Two clients provisioning the same /32 against one server endpoint
// produce indistinguishable peers. Errors are attributed to every source server
// that contributed a colliding outbound.
func checkAmneziaWGAllowedIPsCollision(configs map[string]config.Config) map[string][]error {
	const minOwnersForCollision = 2

	// key: server + inbound + address -> list of source servers.
	type claim struct{ server, inbound, address string }
	owners := make(map[claim][]string)

	for srcName, cfg := range configs {
		for _, out := range cfg.Outbounds {
			if out.Type != generate.TypeAmneziaWG || out.Server == "" || out.Inbound == "" || len(out.Address) == 0 {
				continue
			}
			key := claim{out.Server, out.Inbound, out.Address[0]}
			owners[key] = append(owners[key], srcName)
		}
	}

	result := make(map[string][]error)
	for c, sources := range owners {
		if len(sources) < minOwnersForCollision {
			continue
		}
		sort.Strings(sources)
		msg := fmt.Sprintf(
			"amneziawg outbound address %q for server %q inbound %q is shared by multiple clients: %s",
			c.address, c.server, c.inbound, strings.Join(sources, ", "))
		// Attribute to each source server that contributed a colliding outbound.
		// Dedup in case one server has two outbounds with the same address+target.
		seen := make(map[string]bool, len(sources))
		for _, s := range sources {
			if seen[s] {
				continue
			}
			seen[s] = true
			result[s] = append(result[s], errors.New(msg))
		}
	}
	return result
}
