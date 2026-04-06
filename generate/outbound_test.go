package generate

import (
	"testing"

	"github.com/Arsolitt/cheburbox/config"
)

func TestBuildDirectOutbound(t *testing.T) {
	t.Parallel()

	out := config.Outbound{Type: "direct", Tag: "direct"}
	result, err := BuildOutbound(out)
	if err != nil {
		t.Fatalf("BuildOutbound: %v", err)
	}
	if result.Tag != "direct" {
		t.Errorf("Tag = %q, want direct", result.Tag)
	}
	if result.Type != "direct" {
		t.Errorf("Type = %q, want direct", result.Type)
	}
}

func TestBuildURLTestOutbound(t *testing.T) {
	t.Parallel()

	out := config.Outbound{
		Type:      "urltest",
		Tag:       "proxy",
		URL:       "https://www.gstatic.com/generate_204",
		Interval:  "3m",
		Outbounds: []string{"vless-out", "hy2-out"},
	}
	result, err := BuildOutbound(out)
	if err != nil {
		t.Fatalf("BuildOutbound: %v", err)
	}
	if result.Tag != "proxy" {
		t.Errorf("Tag = %q, want proxy", result.Tag)
	}
	if result.Type != "urltest" {
		t.Errorf("Type = %q, want urltest", result.Type)
	}
}

func TestBuildSelectorOutbound(t *testing.T) {
	t.Parallel()

	out := config.Outbound{
		Type:      "selector",
		Tag:       "manual-proxy",
		Outbounds: []string{"vless-out", "hy2-out"},
	}
	result, err := BuildOutbound(out)
	if err != nil {
		t.Fatalf("BuildOutbound: %v", err)
	}
	if result.Tag != "manual-proxy" {
		t.Errorf("Tag = %q, want manual-proxy", result.Tag)
	}
	if result.Type != "selector" {
		t.Errorf("Type = %q, want selector", result.Type)
	}
}

func TestBuildOutboundCrossServerSkipped(t *testing.T) {
	t.Parallel()

	out := config.Outbound{
		Type:    "vless",
		Tag:     "remote-vless",
		Server:  "other-server",
		Inbound: "vless-in",
	}
	_, err := BuildOutbound(out)
	if err == nil {
		t.Fatal("expected error for cross-server outbound in Phase 2")
	}
}

func TestBuildOutboundUnknownType(t *testing.T) {
	t.Parallel()

	out := config.Outbound{Type: "shadowsocks", Tag: "ss-out"}
	_, err := BuildOutbound(out)
	if err == nil {
		t.Fatal("expected error for unknown outbound type")
	}
}
