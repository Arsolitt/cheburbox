package validate

import (
	"strings"
	"testing"

	"github.com/Arsolitt/cheburbox/config"
)

func TestCheckHysteria2ServerNameCollision(t *testing.T) {
	t.Parallel()

	cfg := config.Config{
		Inbounds: []config.Inbound{
			{Type: "hysteria2", Tag: "hy2-a", TLS: &config.InboundTLS{ServerName: "example.com"}},
			{Type: "hysteria2", Tag: "hy2-b", TLS: &config.InboundTLS{ServerName: "example.com"}},
		},
	}

	errs := checkHysteria2ServerNameCollision("srv1", cfg)
	if len(errs) != 1 {
		t.Fatalf("expected 1 error, got %d: %v", len(errs), errs)
	}

	if !strings.Contains(errs[0].Error(), "hy2-a") || !strings.Contains(errs[0].Error(), "hy2-b") {
		t.Errorf("error should mention both tags, got: %v", errs[0])
	}

	if !strings.Contains(errs[0].Error(), "example.com") {
		t.Errorf("error should mention server_name, got: %v", errs[0])
	}
}

func TestCheckHysteria2ServerNameCollisionNoConflict(t *testing.T) {
	t.Parallel()

	cfg := config.Config{
		Inbounds: []config.Inbound{
			{Type: "hysteria2", Tag: "hy2-a", TLS: &config.InboundTLS{ServerName: "alpha.com"}},
			{Type: "hysteria2", Tag: "hy2-b", TLS: &config.InboundTLS{ServerName: "beta.com"}},
		},
	}

	errs := checkHysteria2ServerNameCollision("srv1", cfg)
	if len(errs) != 0 {
		t.Fatalf("expected 0 errors, got %d: %v", len(errs), errs)
	}
}

func TestCheckHysteria2ServerNameCollisionNoTLS(t *testing.T) {
	t.Parallel()

	cfg := config.Config{
		Inbounds: []config.Inbound{
			{Type: "hysteria2", Tag: "hy2-a"},
			{Type: "hysteria2", Tag: "hy2-b"},
		},
	}

	errs := checkHysteria2ServerNameCollision("srv1", cfg)
	if len(errs) != 0 {
		t.Fatalf("expected 0 errors, got %d: %v", len(errs), errs)
	}
}

func TestCheckHysteria2ServerNameCollisionNonHysteria2(t *testing.T) {
	t.Parallel()

	cfg := config.Config{
		Inbounds: []config.Inbound{
			{Type: "vless", Tag: "vl-a", TLS: &config.InboundTLS{ServerName: "example.com"}},
		},
	}

	errs := checkHysteria2ServerNameCollision("srv1", cfg)
	if len(errs) != 0 {
		t.Fatalf("expected 0 errors, got %d: %v", len(errs), errs)
	}
}

func TestCheckHysteria2ServerNameCollisionThreeWay(t *testing.T) {
	t.Parallel()

	cfg := config.Config{
		Inbounds: []config.Inbound{
			{Type: "hysteria2", Tag: "hy2-a", TLS: &config.InboundTLS{ServerName: "shared.com"}},
			{Type: "hysteria2", Tag: "hy2-b", TLS: &config.InboundTLS{ServerName: "other.com"}},
			{Type: "hysteria2", Tag: "hy2-c", TLS: &config.InboundTLS{ServerName: "shared.com"}},
		},
	}

	errs := checkHysteria2ServerNameCollision("srv1", cfg)
	if len(errs) != 1 {
		t.Fatalf("expected 1 error, got %d: %v", len(errs), errs)
	}

	if !strings.Contains(errs[0].Error(), "hy2-a") || !strings.Contains(errs[0].Error(), "hy2-c") {
		t.Errorf("error should mention colliding tags, got: %v", errs[0])
	}
}

func TestCheckOutboundInboundRefs(t *testing.T) {
	t.Parallel()

	configs := map[string]config.Config{
		"server-a": {
			Inbounds: []config.Inbound{
				{Type: "hysteria2", Tag: "hy2-in"},
			},
			Outbounds: []config.Outbound{
				{Type: "hysteria2", Tag: "cross-out", Server: "server-b", Inbound: "hy2-in-b"},
			},
		},
		"server-b": {
			Inbounds: []config.Inbound{
				{Type: "hysteria2", Tag: "hy2-in-b"},
			},
		},
	}

	errs := checkOutboundInboundRefs(configs)
	if len(errs) != 0 {
		t.Fatalf("expected 0 errors, got %d: %v", len(errs), errs)
	}
}

func TestCheckOutboundInboundRefsMissing(t *testing.T) {
	t.Parallel()

	configs := map[string]config.Config{
		"server-a": {
			Outbounds: []config.Outbound{
				{Type: "hysteria2", Tag: "cross-out", Server: "server-b", Inbound: "nonexistent"},
			},
		},
		"server-b": {
			Inbounds: []config.Inbound{
				{Type: "hysteria2", Tag: "hy2-in-b"},
			},
		},
	}

	errs := checkOutboundInboundRefs(configs)
	if len(errs) != 1 {
		t.Fatalf("expected 1 error, got %d: %v", len(errs), errs)
	}

	if !strings.Contains(errs[0].Error(), "nonexistent") {
		t.Errorf("error should mention missing inbound tag, got: %v", errs[0])
	}
}

func TestCheckOutboundInboundRefsNoCrossServer(t *testing.T) {
	t.Parallel()

	configs := map[string]config.Config{
		"server-a": {
			Outbounds: []config.Outbound{
				{Type: "direct", Tag: "direct-out"},
			},
		},
	}

	errs := checkOutboundInboundRefs(configs)
	if len(errs) != 0 {
		t.Fatalf("expected 0 errors, got %d: %v", len(errs), errs)
	}
}

func TestCheckOutboundGroupRefsValid(t *testing.T) {
	t.Parallel()

	cfg := config.Config{
		Outbounds: []config.Outbound{
			{Type: "direct", Tag: "direct"},
			{Type: "urltest", Tag: "group-a", Outbounds: []string{"direct"}},
			{Type: "selector", Tag: "group-b", Outbounds: []string{"direct", "group-a"}},
		},
	}

	errs := checkOutboundGroupRefs("srv1", cfg)
	if len(errs) != 0 {
		t.Fatalf("expected 0 errors, got %d: %v", len(errs), errs)
	}
}

func TestCheckOutboundGroupRefsInvalid(t *testing.T) {
	t.Parallel()

	cfg := config.Config{
		Outbounds: []config.Outbound{
			{Type: "direct", Tag: "direct"},
			{Type: "urltest", Tag: "group-a", Outbounds: []string{"direct", "unknown-out"}},
		},
	}

	errs := checkOutboundGroupRefs("srv1", cfg)
	if len(errs) != 1 {
		t.Fatalf("expected 1 error, got %d: %v", len(errs), errs)
	}

	if !strings.Contains(errs[0].Error(), "unknown-out") {
		t.Errorf("error should mention unknown outbound tag, got: %v", errs[0])
	}
}

func TestCheckOutboundGroupRefsNonGroupOutbound(t *testing.T) {
	t.Parallel()

	cfg := config.Config{
		Outbounds: []config.Outbound{
			{Type: "direct", Tag: "direct"},
			{Type: "hysteria2", Tag: "hy2-out"},
		},
	}

	errs := checkOutboundGroupRefs("srv1", cfg)
	if len(errs) != 0 {
		t.Fatalf("expected 0 errors, got %d: %v", len(errs), errs)
	}
}

func TestCheckOutboundGroupRefsEmptyOutbounds(t *testing.T) {
	t.Parallel()

	cfg := config.Config{
		Outbounds: []config.Outbound{
			{Type: "urltest", Tag: "group-a", Outbounds: []string{}},
		},
	}

	errs := checkOutboundGroupRefs("srv1", cfg)
	if len(errs) != 0 {
		t.Fatalf("expected 0 errors, got %d: %v", len(errs), errs)
	}
}
