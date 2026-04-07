package generate

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/option"

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
		t.Fatal("expected error for cross-server outbound without state")
	}
	if !strings.Contains(err.Error(), "server state") {
		t.Errorf("error = %q, want message about server state", err.Error())
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

func TestBuildDirectOutboundDomainResolver(t *testing.T) {
	t.Parallel()

	out := config.Outbound{Type: "direct", Tag: "direct", DomainResolver: "dns-local"}
	result, err := BuildOutbound(out)
	if err != nil {
		t.Fatalf("BuildOutbound: %v", err)
	}

	opts, ok := result.Options.(*option.DirectOutboundOptions)
	if !ok {
		t.Fatalf("Options type = %T, want *option.DirectOutboundOptions", result.Options)
	}
	if opts.DomainResolver == nil {
		t.Fatal("DomainResolver is nil, want non-nil")
	}
	if opts.DomainResolver.Server != "dns-local" {
		t.Errorf("DomainResolver.Server = %q, want dns-local", opts.DomainResolver.Server)
	}
}

func TestBuildDirectOutboundNoDomainResolver(t *testing.T) {
	t.Parallel()

	out := config.Outbound{Type: "direct", Tag: "direct"}
	result, err := BuildOutbound(out)
	if err != nil {
		t.Fatalf("BuildOutbound: %v", err)
	}

	opts := result.Options.(*option.DirectOutboundOptions)
	if opts.DomainResolver != nil {
		t.Errorf("DomainResolver = %v, want nil", opts.DomainResolver)
	}
}

func TestBuildVlessCrossServerOutbound(t *testing.T) {
	t.Parallel()

	state := NewServerState()
	state.StoreEndpoint("remote", "1.2.3.4:443")
	state.StoreInboundCredentials("remote", "vless-in", InboundCredentials{
		Users: map[string]UserCreds{
			"alice": {UUID: "test-uuid-1234", Flow: "xtls-rprx-vision"},
		},
		Reality: &RealityKeys{
			PublicKey: "pub-key-abc",
			ShortID:   []string{"abcdef"},
		},
	})

	out := config.Outbound{
		Type:    "vless",
		Tag:     "remote-vless",
		Server:  "remote",
		Inbound: "vless-in",
		User:    "alice",
		Flow:    "xtls-rprx-vision",
	}

	result, err := BuildOutboundWithState(out, state)
	if err != nil {
		t.Fatalf("BuildOutboundWithState: %v", err)
	}
	if result.Type != "vless" {
		t.Errorf("Type = %q, want vless", result.Type)
	}
	if result.Tag != "remote-vless" {
		t.Errorf("Tag = %q, want remote-vless", result.Tag)
	}

	opts, ok := result.Options.(*option.VLESSOutboundOptions)
	if !ok {
		t.Fatalf("Options type = %T, want *option.VLESSOutboundOptions", result.Options)
	}
	if opts.Server != "1.2.3.4" {
		t.Errorf("Server = %q, want 1.2.3.4", opts.Server)
	}
	if opts.ServerPort != 443 {
		t.Errorf("ServerPort = %d, want 443", opts.ServerPort)
	}
	if opts.UUID != "test-uuid-1234" {
		t.Errorf("UUID = %q, want test-uuid-1234", opts.UUID)
	}
	if opts.Flow != "xtls-rprx-vision" {
		t.Errorf("Flow = %q, want xtls-rprx-vision", opts.Flow)
	}
	if opts.TLS == nil {
		t.Fatal("TLS is nil, want non-nil")
	}
	if !opts.TLS.Enabled {
		t.Error("TLS.Enabled = false, want true")
	}
	if opts.TLS.Reality == nil {
		t.Fatal("TLS.Reality is nil, want non-nil")
	}
	if opts.TLS.Reality.PublicKey != "pub-key-abc" {
		t.Errorf("Reality.PublicKey = %q, want pub-key-abc", opts.TLS.Reality.PublicKey)
	}
	if opts.TLS.Reality.ShortID != "abcdef" {
		t.Errorf("Reality.ShortID = %q, want abcdef", opts.TLS.Reality.ShortID)
	}
	if !opts.TLS.Reality.Enabled {
		t.Error("Reality.Enabled = false, want true")
	}
}

func TestBuildHysteria2CrossServerOutbound(t *testing.T) {
	t.Parallel()

	state := NewServerState()
	state.StoreEndpoint("remote", "5.6.7.8:8443")
	state.StoreInboundCredentials("remote", "hy2-in", InboundCredentials{
		Users:        map[string]UserCreds{"bob": {Password: "secret-pw"}},
		ObfsPassword: "obfs-secret",
	})

	pinBytes := make([]byte, 32)
	pinBytes[0] = 0xAA
	pin := "sha256/" + base64.RawURLEncoding.EncodeToString(pinBytes)
	state.StorePinSHA256("remote", "hy2-in", pin)

	out := config.Outbound{
		Type:    "hysteria2",
		Tag:     "remote-hy2",
		Server:  "remote",
		Inbound: "hy2-in",
		User:    "bob",
	}

	result, err := BuildOutboundWithState(out, state)
	if err != nil {
		t.Fatalf("BuildOutboundWithState: %v", err)
	}
	if result.Type != "hysteria2" {
		t.Errorf("Type = %q, want hysteria2", result.Type)
	}

	opts, ok := result.Options.(*option.Hysteria2OutboundOptions)
	if !ok {
		t.Fatalf("Options type = %T, want *option.Hysteria2OutboundOptions", result.Options)
	}
	if opts.Server != "5.6.7.8" {
		t.Errorf("Server = %q, want 5.6.7.8", opts.Server)
	}
	if opts.ServerPort != 8443 {
		t.Errorf("ServerPort = %d, want 8443", opts.ServerPort)
	}
	if opts.Password != "secret-pw" {
		t.Errorf("Password = %q, want secret-pw", opts.Password)
	}
	if opts.Obfs == nil {
		t.Fatal("Obfs is nil, want non-nil")
	}
	if opts.Obfs.Type != "salamander" {
		t.Errorf("Obfs.Type = %q, want salamander", opts.Obfs.Type)
	}
	if opts.Obfs.Password != "obfs-secret" {
		t.Errorf("Obfs.Password = %q, want obfs-secret", opts.Obfs.Password)
	}
	if opts.TLS == nil {
		t.Fatal("TLS is nil, want non-nil")
	}
	if !opts.TLS.Enabled {
		t.Error("TLS.Enabled = false, want true")
	}
	if len(opts.TLS.CertificatePublicKeySHA256) != 1 {
		t.Fatalf("CertificatePublicKeySHA256 length = %d, want 1", len(opts.TLS.CertificatePublicKeySHA256))
	}
	if !bytes.Equal(opts.TLS.CertificatePublicKeySHA256[0], pinBytes) {
		t.Error("CertificatePublicKeySHA256[0] does not match expected pin bytes")
	}
}

func TestBuildVlessCrossServerEndpointOverride(t *testing.T) {
	t.Parallel()

	state := NewServerState()
	state.StoreEndpoint("remote", "1.2.3.4:443")
	state.StoreInboundCredentials("remote", "vless-in", InboundCredentials{
		Users: map[string]UserCreds{
			"alice": {UUID: "test-uuid"},
		},
	})

	out := config.Outbound{
		Type:     "vless",
		Tag:      "remote-vless",
		Server:   "remote",
		Inbound:  "vless-in",
		User:     "alice",
		Endpoint: "5.6.7.8:8443",
	}

	result, err := BuildOutboundWithState(out, state)
	if err != nil {
		t.Fatalf("BuildOutboundWithState: %v", err)
	}

	opts := result.Options.(*option.VLESSOutboundOptions)
	if opts.Server != "5.6.7.8" {
		t.Errorf("Server = %q, want 5.6.7.8 (from endpoint override)", opts.Server)
	}
	if opts.ServerPort != 8443 {
		t.Errorf("ServerPort = %d, want 8443 (from endpoint override)", opts.ServerPort)
	}
}

func TestBuildCrossServerOutboundUserNotFound(t *testing.T) {
	t.Parallel()

	state := NewServerState()
	state.StoreEndpoint("remote", "1.2.3.4:443")
	state.StoreInboundCredentials("remote", "vless-in", InboundCredentials{
		Users: map[string]UserCreds{
			"alice": {UUID: "test-uuid"},
		},
	})

	out := config.Outbound{
		Type:    "vless",
		Tag:     "remote-vless",
		Server:  "remote",
		Inbound: "vless-in",
		User:    "nonexistent",
	}

	_, err := BuildOutboundWithState(out, state)
	if err == nil {
		t.Fatal("expected error for nonexistent user")
	}
	if !strings.Contains(err.Error(), "nonexistent") {
		t.Errorf("error = %q, want message about nonexistent user", err.Error())
	}
}

func TestBuildCrossServerOutboundNoState(t *testing.T) {
	t.Parallel()

	out := config.Outbound{
		Type:    "vless",
		Tag:     "remote-vless",
		Server:  "remote",
		Inbound: "vless-in",
		User:    "alice",
	}

	_, err := BuildOutbound(out)
	if err == nil {
		t.Fatal("expected error for cross-server outbound without state")
	}
	if !strings.Contains(err.Error(), "server state") {
		t.Errorf("error = %q, want message about server state", err.Error())
	}
}

func TestBuildVlessCrossServerDefaultUser(t *testing.T) {
	t.Parallel()

	state := NewServerState()
	state.StoreEndpoint("remote", "1.2.3.4:443")
	state.StoreInboundCredentials("remote", "vless-in", InboundCredentials{
		Users: map[string]UserCreds{
			"alice": {UUID: "alice-uuid"},
			"bob":   {UUID: "bob-uuid"},
		},
	})

	out := config.Outbound{
		Type:    "vless",
		Tag:     "remote-vless",
		Server:  "remote",
		Inbound: "vless-in",
	}

	result, err := BuildOutboundWithState(out, state, WithDefaultUser("bob"))
	if err != nil {
		t.Fatalf("BuildOutboundWithState: %v", err)
	}

	opts := result.Options.(*option.VLESSOutboundOptions)
	if opts.UUID != "bob-uuid" {
		t.Errorf("UUID = %q, want bob-uuid (from default user)", opts.UUID)
	}
}

func TestBuildVlessCrossServerNoCredentials(t *testing.T) {
	t.Parallel()

	state := NewServerState()
	state.StoreEndpoint("remote", "1.2.3.4:443")

	out := config.Outbound{
		Type:    "vless",
		Tag:     "remote-vless",
		Server:  "remote",
		Inbound: "vless-in",
		User:    "alice",
	}

	_, err := BuildOutboundWithState(out, state)
	if err == nil {
		t.Fatal("expected error for missing credentials")
	}
	if !strings.Contains(err.Error(), "no credentials") {
		t.Errorf("error = %q, want message about no credentials", err.Error())
	}
}

func TestBuildVlessCrossServerNoEndpoint(t *testing.T) {
	t.Parallel()

	state := NewServerState()
	state.StoreInboundCredentials("remote", "vless-in", InboundCredentials{
		Users: map[string]UserCreds{
			"alice": {UUID: "test-uuid"},
		},
	})

	out := config.Outbound{
		Type:    "vless",
		Tag:     "remote-vless",
		Server:  "remote",
		Inbound: "vless-in",
		User:    "alice",
	}

	_, err := BuildOutboundWithState(out, state)
	if err == nil {
		t.Fatal("expected error for missing endpoint")
	}
	if !strings.Contains(err.Error(), "no endpoint") {
		t.Errorf("error = %q, want message about no endpoint", err.Error())
	}
}

func TestBuildVlessCrossServerNoReality(t *testing.T) {
	t.Parallel()

	state := NewServerState()
	state.StoreEndpoint("remote", "1.2.3.4:443")
	state.StoreInboundCredentials("remote", "vless-in", InboundCredentials{
		Users: map[string]UserCreds{
			"alice": {UUID: "test-uuid"},
		},
	})

	out := config.Outbound{
		Type:    "vless",
		Tag:     "remote-vless",
		Server:  "remote",
		Inbound: "vless-in",
		User:    "alice",
	}

	result, err := BuildOutboundWithState(out, state)
	if err != nil {
		t.Fatalf("BuildOutboundWithState: %v", err)
	}

	opts := result.Options.(*option.VLESSOutboundOptions)
	if opts.TLS != nil {
		t.Errorf("TLS = %+v, want nil (no reality configured)", opts.TLS)
	}
}

func TestBuildVlessCrossServerEmptyShortID(t *testing.T) {
	t.Parallel()

	state := NewServerState()
	state.StoreEndpoint("remote", "1.2.3.4:443")
	state.StoreInboundCredentials("remote", "vless-in", InboundCredentials{
		Users: map[string]UserCreds{
			"alice": {UUID: "test-uuid"},
		},
		Reality: &RealityKeys{
			PublicKey: "pub-key",
			ShortID:   []string{},
		},
	})

	out := config.Outbound{
		Type:    "vless",
		Tag:     "remote-vless",
		Server:  "remote",
		Inbound: "vless-in",
		User:    "alice",
	}

	result, err := BuildOutboundWithState(out, state)
	if err != nil {
		t.Fatalf("BuildOutboundWithState: %v", err)
	}

	opts := result.Options.(*option.VLESSOutboundOptions)
	if opts.TLS.Reality.ShortID != "" {
		t.Errorf("Reality.ShortID = %q, want empty string", opts.TLS.Reality.ShortID)
	}
}

func TestBuildHysteria2CrossServerNoPin(t *testing.T) {
	t.Parallel()

	state := NewServerState()
	state.StoreEndpoint("remote", "5.6.7.8:8443")
	state.StoreInboundCredentials("remote", "hy2-in", InboundCredentials{
		Users: map[string]UserCreds{"bob": {Password: "secret-pw"}},
	})

	out := config.Outbound{
		Type:    "hysteria2",
		Tag:     "remote-hy2",
		Server:  "remote",
		Inbound: "hy2-in",
		User:    "bob",
	}

	result, err := BuildOutboundWithState(out, state)
	if err != nil {
		t.Fatalf("BuildOutboundWithState: %v", err)
	}

	opts := result.Options.(*option.Hysteria2OutboundOptions)
	if len(opts.TLS.CertificatePublicKeySHA256) != 0 {
		t.Errorf("CertificatePublicKeySHA256 = %v, want empty", opts.TLS.CertificatePublicKeySHA256)
	}
}

func TestBuildHysteria2CrossServerNoObfs(t *testing.T) {
	t.Parallel()

	state := NewServerState()
	state.StoreEndpoint("remote", "5.6.7.8:8443")
	state.StoreInboundCredentials("remote", "hy2-in", InboundCredentials{
		Users: map[string]UserCreds{"bob": {Password: "secret-pw"}},
	})

	out := config.Outbound{
		Type:    "hysteria2",
		Tag:     "remote-hy2",
		Server:  "remote",
		Inbound: "hy2-in",
		User:    "bob",
	}

	result, err := BuildOutboundWithState(out, state)
	if err != nil {
		t.Fatalf("BuildOutboundWithState: %v", err)
	}

	opts := result.Options.(*option.Hysteria2OutboundOptions)
	if opts.Obfs != nil {
		t.Errorf("Obfs = %+v, want nil", opts.Obfs)
	}
}

func TestBuildCrossServerNoUserNoDefault(t *testing.T) {
	t.Parallel()

	state := NewServerState()
	state.StoreEndpoint("remote", "1.2.3.4:443")
	state.StoreInboundCredentials("remote", "vless-in", InboundCredentials{
		Users: map[string]UserCreds{
			"alice": {UUID: "test-uuid"},
		},
	})

	out := config.Outbound{
		Type:    "vless",
		Tag:     "remote-vless",
		Server:  "remote",
		Inbound: "vless-in",
	}

	_, err := BuildOutboundWithState(out, state)
	if err == nil {
		t.Fatal("expected error when no user specified and no default")
	}
	if !strings.Contains(err.Error(), "no user specified") {
		t.Errorf("error = %q, want message about no user", err.Error())
	}
}

func TestDecodePinSHA256(t *testing.T) {
	t.Parallel()

	original := make([]byte, 32)
	original[0] = 0xAB
	original[31] = 0xCD

	encoded := "sha256/" + base64.RawURLEncoding.EncodeToString(original)
	decoded, err := decodePinSHA256(encoded)
	if err != nil {
		t.Fatalf("decodePinSHA256: %v", err)
	}
	if !bytes.Equal(decoded, original) {
		t.Error("decoded bytes do not match original")
	}
}

func TestDecodePinSHA256InvalidFormat(t *testing.T) {
	t.Parallel()

	_, err := decodePinSHA256("invalid")
	if err == nil {
		t.Fatal("expected error for invalid pin format")
	}
}

func TestDecodePinSHA256InvalidBase64(t *testing.T) {
	t.Parallel()

	_, err := decodePinSHA256("sha256/!!!invalid-base64!!!")
	if err == nil {
		t.Fatal("expected error for invalid base64")
	}
}
