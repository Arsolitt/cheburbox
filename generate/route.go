package generate

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	singjson "github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/json/badoption"

	"github.com/Arsolitt/cheburbox/config"
)

// ConvertRoute converts cheburbox route configuration to sing-box RouteOptions.
// Returns an empty RouteOptions if route is nil.
func ConvertRoute(route *config.Route) (*option.RouteOptions, error) {
	if route == nil {
		return &option.RouteOptions{}, nil
	}

	ctx := include.Context(context.Background())

	routeOpts := &option.RouteOptions{
		Final:               route.Final,
		AutoDetectInterface: route.AutoDetectInterface,
	}

	if route.DefaultDomainResolver != "" {
		routeOpts.DefaultDomainResolver = &option.DomainResolveOptions{
			Server: route.DefaultDomainResolver,
		}
	}

	if len(route.Rules) > 0 {
		var rules []option.Rule
		if err := singjson.UnmarshalContext(ctx, route.Rules, &rules); err != nil {
			return nil, fmt.Errorf("unmarshal rules: %w", err)
		}
		routeOpts.Rules = rules
	}

	if len(route.RuleSets) > 0 {
		var ruleSets []option.RuleSet
		if err := singjson.UnmarshalContext(ctx, route.RuleSets, &ruleSets); err != nil {
			return nil, fmt.Errorf("unmarshal rule_sets: %w", err)
		}
		for i, rs := range ruleSets {
			//nolint:staticcheck // deliberate deprecated-field read: fail fast on download_detour instead of silently passing it through.
			if rs.RemoteOptions.DownloadDetour != "" {
				return nil, fmt.Errorf(
					"rule_sets[%d] %q: download_detour is deprecated in sing-box 1.14 (removed in 1.16); use http_client instead",
					i,
					strings.Join(rs.Tag, ","),
				)
			}
		}
		routeOpts.RuleSet = ruleSets
	}

	for _, name := range route.CustomRuleSets {
		rs := option.RuleSet{
			Type: C.RuleSetTypeLocal,
			Tag:  badoption.Listable[string]{name},
			LocalOptions: option.LocalRuleSet{
				Path: filepath.Join("rule-set", name+".srs"),
			},
		}
		routeOpts.RuleSet = append(routeOpts.RuleSet, rs)
	}

	return routeOpts, nil
}
