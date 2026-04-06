package generate

import (
	"encoding/json"
	"testing"

	"github.com/sagernet/sing-box/option"

	"github.com/Arsolitt/cheburbox/config"
)

func TestConvertDNS(t *testing.T) {
	t.Parallel()

	cfg := config.DNS{
		Final:    new("dns-remote"),
		Strategy: new("prefer_ipv4"),
		Servers: []config.DNSServer{
			{Type: "local", Tag: "dns-local"},
			{Type: "tls", Tag: "dns-remote", Server: "8.8.8.8", ServerPort: 853, Detour: "direct"},
		},
	}

	opts, err := ConvertDNS(cfg)
	if err != nil {
		t.Fatalf("ConvertDNS: %v", err)
	}

	if opts.Final != "dns-remote" {
		t.Errorf("Final = %q, want %q", opts.Final, "dns-remote")
	}
	if opts.Strategy.String() != "prefer_ipv4" {
		t.Errorf("Strategy = %q, want %q", opts.Strategy, "prefer_ipv4")
	}
	if len(opts.Servers) != 2 {
		t.Fatalf("Servers count = %d, want 2", len(opts.Servers))
	}
	if opts.Servers[0].Type != "local" {
		t.Errorf("Servers[0].Type = %q, want local", opts.Servers[0].Type)
	}
	if opts.Servers[1].Type != "tls" {
		t.Errorf("Servers[1].Type = %q, want tls", opts.Servers[1].Type)
	}

	tlsOpts, ok := opts.Servers[1].Options.(*option.RemoteTLSDNSServerOptions)
	if !ok {
		t.Fatal("Servers[1].Options is not *option.RemoteTLSDNSServerOptions")
	}
	if tlsOpts.Server != "8.8.8.8" {
		t.Errorf("TLS server = %q, want %q", tlsOpts.Server, "8.8.8.8")
	}
	if tlsOpts.ServerPort != 853 {
		t.Errorf("TLS server_port = %d, want %d", tlsOpts.ServerPort, 853)
	}
	if tlsOpts.Detour != "direct" {
		t.Errorf("TLS detour = %q, want %q", tlsOpts.Detour, "direct")
	}
}

func TestConvertDNSMinimal(t *testing.T) {
	t.Parallel()

	cfg := config.DNS{
		Servers: []config.DNSServer{
			{Type: "local", Tag: "dns-local"},
		},
	}

	opts, err := ConvertDNS(cfg)
	if err != nil {
		t.Fatalf("ConvertDNS: %v", err)
	}

	if opts.Final != "" {
		t.Errorf("Final = %q, want empty", opts.Final)
	}
	if opts.Strategy.String() != "" {
		t.Errorf("Strategy = %q, want empty", opts.Strategy)
	}
	if len(opts.Servers) != 1 {
		t.Fatalf("Servers count = %d, want 1", len(opts.Servers))
	}
}

func TestConvertDNSUnknownServerType(t *testing.T) {
	t.Parallel()

	cfg := config.DNS{
		Servers: []config.DNSServer{
			{Type: "unknown", Tag: "dns-unknown"},
		},
	}

	_, err := ConvertDNS(cfg)
	if err == nil {
		t.Fatal("expected error for unknown DNS server type")
	}
}

func TestConvertDNSWithRules(t *testing.T) {
	t.Parallel()

	rulesJSON := json.RawMessage(`[{
		"rule_set": ["geosite-category-ru"],
		"action": "route",
		"server": "dns-local"
	}]`)

	cfg := config.DNS{
		Final:   new("dns-remote"),
		Servers: []config.DNSServer{{Type: "local", Tag: "dns-local"}},
		Rules:   rulesJSON,
	}

	opts, err := ConvertDNS(cfg)
	if err != nil {
		t.Fatalf("ConvertDNS: %v", err)
	}

	if len(opts.Rules) != 1 {
		t.Fatalf("Rules count = %d, want 1", len(opts.Rules))
	}
}

func TestConvertDNSNoRules(t *testing.T) {
	t.Parallel()

	cfg := config.DNS{
		Servers: []config.DNSServer{{Type: "local", Tag: "dns-local"}},
	}

	opts, err := ConvertDNS(cfg)
	if err != nil {
		t.Fatalf("ConvertDNS: %v", err)
	}

	if len(opts.Rules) != 0 {
		t.Errorf("Rules count = %d, want 0", len(opts.Rules))
	}
}
