// Package validate provides configuration validation in two phases.
//
// Phase 1 validates cheburbox.json configs for each server independently
// (intra-server checks such as hysteria2 server_name collisions).
//
// Phase 2 validates generated sing-box configs across all servers
// (cross-server checks).
package validate

import (
	"fmt"

	"github.com/Arsolitt/cheburbox/config"
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
