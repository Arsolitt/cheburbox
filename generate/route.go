package generate

import (
	"context"
	"fmt"
	"path/filepath"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	singjson "github.com/sagernet/sing/common/json"

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
		routeOpts.RuleSet = ruleSets
	}

	for _, name := range route.CustomRuleSets {
		rs := option.RuleSet{
			Type: C.RuleSetTypeLocal,
			Tag:  name,
			LocalOptions: option.LocalRuleSet{
				Path: filepath.Join("rule-set", name+".srs"),
			},
		}
		routeOpts.RuleSet = append(routeOpts.RuleSet, rs)
	}

	return routeOpts, nil
}
