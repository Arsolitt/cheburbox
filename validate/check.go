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

	"github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/include"
	singjson "github.com/sagernet/sing/common/json"

	"github.com/Arsolitt/cheburbox/config"
	"github.com/Arsolitt/cheburbox/generate"
)

// checkHysteria2ServerNameCollision detects hysteria2 inbounds that share
// the same tls.server_name, which would cause cert file conflicts.
//
//nolint:unparam // server parameter is used by callers with different server names.
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

// ptr returns a pointer to the given string value.
func ptr(s string) *string {
	return &s
}

// checkOutboundGroupRefs validates that urltest and selector outbound groups
// reference only outbound tags that exist in the same server.
//
//nolint:unparam // server parameter is used by callers with different server names.
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
