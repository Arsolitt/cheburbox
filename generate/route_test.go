package generate

import (
	"encoding/json"
	"testing"

	"github.com/Arsolitt/cheburbox/config"
)

func TestConvertRoute(t *testing.T) {
	t.Parallel()

	route := &config.Route{
		Final:               "direct",
		AutoDetectInterface: true,
		CustomRuleSets:      []string{"extension", "fastly"},
	}

	opts, err := ConvertRoute(route)
	if err != nil {
		t.Fatalf("ConvertRoute: %v", err)
	}

	if opts.Final != "direct" {
		t.Errorf("Final = %q, want %q", opts.Final, "direct")
	}
	if !opts.AutoDetectInterface {
		t.Error("AutoDetectInterface = false, want true")
	}
}

func TestConvertRouteNil(t *testing.T) {
	t.Parallel()

	opts, err := ConvertRoute(nil)
	if err != nil {
		t.Fatalf("ConvertRoute nil: %v", err)
	}
	if opts == nil {
		t.Fatal("expected non-nil RouteOptions for nil route input")
	}
	if opts.Final != "" {
		t.Errorf("Final = %q, want empty for nil input", opts.Final)
	}
}

func TestConvertRouteWithRules(t *testing.T) {
	t.Parallel()

	rulesJSON := json.RawMessage(`[{"action": "sniff"}]`)
	ruleSetsJSON := json.RawMessage(`[
		{"type": "remote", "tag": "geoip", "url": "https://example.com/geoip.json", "format": "binary"}
	]`)

	route := &config.Route{
		Final:          "proxy",
		Rules:          rulesJSON,
		RuleSets:       ruleSetsJSON,
		CustomRuleSets: []string{"extension"},
	}

	opts, err := ConvertRoute(route)
	if err != nil {
		t.Fatalf("ConvertRoute: %v", err)
	}

	if len(opts.Rules) != 1 {
		t.Fatalf("Rules count = %d, want 1", len(opts.Rules))
	}
	if opts.Rules[0].DefaultOptions.Action != "sniff" {
		t.Errorf("Rules[0].Action = %q, want %q", opts.Rules[0].DefaultOptions.Action, "sniff")
	}
	if len(opts.RuleSet) != 2 {
		t.Fatalf("RuleSet count = %d, want 2 (1 remote + 1 custom)", len(opts.RuleSet))
	}
	if opts.RuleSet[0].Tag != "geoip" {
		t.Errorf("RuleSet[0].Tag = %q, want %q", opts.RuleSet[0].Tag, "geoip")
	}
	if opts.RuleSet[0].Type != "remote" {
		t.Errorf("RuleSet[0].Type = %q, want %q", opts.RuleSet[0].Type, "remote")
	}
	if opts.RuleSet[1].Tag != "extension" {
		t.Errorf("RuleSet[1].Tag = %q, want %q", opts.RuleSet[1].Tag, "extension")
	}
	if opts.RuleSet[1].Type != "local" {
		t.Errorf("RuleSet[1].Type = %q, want %q", opts.RuleSet[1].Type, "local")
	}
	if opts.RuleSet[1].LocalOptions.Path != "rule-set/extension.srs" {
		t.Errorf("RuleSet[1].Path = %q, want %q", opts.RuleSet[1].LocalOptions.Path, "rule-set/extension.srs")
	}
}

func TestConvertRouteWithCustomRuleSets(t *testing.T) {
	t.Parallel()

	route := &config.Route{
		Final:          "direct",
		CustomRuleSets: []string{"extension", "fastly"},
	}

	opts, err := ConvertRoute(route)
	if err != nil {
		t.Fatalf("ConvertRoute: %v", err)
	}

	localCount := 0
	for _, rs := range opts.RuleSet {
		if rs.Type == "local" {
			localCount++
		}
	}
	if localCount != 2 {
		t.Errorf("expected 2 local rule sets, got %d", localCount)
	}

	paths := map[string]bool{}
	for _, rs := range opts.RuleSet {
		if rs.Type == "local" {
			paths[rs.LocalOptions.Path] = true
		}
	}
	if !paths["rule-set/extension.srs"] {
		t.Error("missing rule-set/extension.srs path")
	}
	if !paths["rule-set/fastly.srs"] {
		t.Error("missing rule-set/fastly.srs path")
	}
}
