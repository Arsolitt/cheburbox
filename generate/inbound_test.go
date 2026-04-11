package generate

import (
	"fmt"
	"net/netip"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/option"

	"github.com/Arsolitt/cheburbox/config"
)

func TestBuildVLESSInbound(t *testing.T) {
	t.Parallel()

	in := config.Inbound{
		Tag:        "vless-in",
		Type:       "vless",
		ListenPort: 443,
		TLS: &config.InboundTLS{
			Reality: &config.RealityConfig{
				Handshake: &config.RealityHandshake{
					Server:     "example.com",
					ServerPort: 443,
				},
				ShortID: []string{"abcd1234"},
			},
		},
		Users: []config.InboundUser{{Name: "alice"}, {Name: "bob"}},
	}

	creds := InboundCredentials{
		Users: map[string]UserCreds{
			"alice": {UUID: "uuid-alice"},
			"bob":   {UUID: "uuid-bob"},
		},
		Reality: &RealityKeys{
			PrivateKey: "priv-key",
			PublicKey:  "pub-key",
			ShortID:    []string{"abcd1234"},
		},
	}

	inbound, err := BuildInbound(in, creds)
	if err != nil {
		t.Fatalf("BuildInbound: %v", err)
	}

	if inbound.Tag != "vless-in" {
		t.Errorf("Tag = %q, want vless-in", inbound.Tag)
	}
	if inbound.Type != "vless" {
		t.Errorf("Type = %q, want vless", inbound.Type)
	}

	opts, ok := inbound.Options.(*vlessInboundOptions)
	if !ok {
		t.Fatalf("Options type = %T, want *vlessInboundOptions", inbound.Options)
	}
	if len(opts.Users) != 2 {
		t.Fatalf("Users count = %d, want 2", len(opts.Users))
	}
	usersByName := make(map[string]string, len(opts.Users))
	for _, u := range opts.Users {
		usersByName[u.Name] = u.UUID
	}
	if usersByName["alice"] != "uuid-alice" {
		t.Errorf("alice UUID = %q, want uuid-alice", usersByName["alice"])
	}
	if usersByName["bob"] != "uuid-bob" {
		t.Errorf("bob UUID = %q, want uuid-bob", usersByName["bob"])
	}
	if opts.ListenPort != 443 {
		t.Errorf("ListenPort = %d, want 443", opts.ListenPort)
	}

	if opts.TLS == nil || opts.TLS.Reality == nil {
		t.Fatal("TLS.Reality is nil, expected reality config")
	}
	if opts.TLS.Reality.PrivateKey != "priv-key" {
		t.Errorf("Reality.PrivateKey = %q, want priv-key", opts.TLS.Reality.PrivateKey)
	}
	if opts.TLS.Reality.Handshake.Server != "example.com" {
		t.Errorf("Reality.Handshake.Server = %q, want example.com", opts.TLS.Reality.Handshake.Server)
	}
	if opts.TLS.Reality.Handshake.ServerPort != 443 {
		t.Errorf("Reality.Handshake.ServerPort = %d, want 443", opts.TLS.Reality.Handshake.ServerPort)
	}
}

func TestBuildVLESSInboundNoTLS(t *testing.T) {
	t.Parallel()

	in := config.Inbound{
		Tag:        "vless-notls",
		Type:       "vless",
		ListenPort: 8080,
		Users:      []config.InboundUser{{Name: "alice"}},
	}

	creds := InboundCredentials{
		Users: map[string]UserCreds{
			"alice": {UUID: "uuid-alice"},
		},
	}

	inbound, err := BuildInbound(in, creds)
	if err != nil {
		t.Fatalf("BuildInbound: %v", err)
	}

	opts, ok := inbound.Options.(*vlessInboundOptions)
	if !ok {
		t.Fatalf("Options type = %T, want *vlessInboundOptions", inbound.Options)
	}
	if opts.TLS != nil {
		t.Error("TLS should be nil when no TLS config provided")
	}
}

func TestBuildVLESSInboundNoUsers(t *testing.T) {
	t.Parallel()

	in := config.Inbound{
		Tag:        "vless-nousers",
		Type:       "vless",
		ListenPort: 443,
	}

	inbound, err := BuildInbound(in, InboundCredentials{})
	if err != nil {
		t.Fatalf("BuildInbound: %v", err)
	}

	opts := inbound.Options.(*vlessInboundOptions)
	if len(opts.Users) != 0 {
		t.Errorf("Users count = %d, want 0", len(opts.Users))
	}
}

func TestBuildHysteria2Inbound(t *testing.T) {
	t.Parallel()

	in := config.Inbound{
		Tag:        "hy2-in",
		Type:       "hysteria2",
		ListenPort: 443,
		UpMbps:     1000,
		DownMbps:   1000,
		TLS: &config.InboundTLS{
			ServerName: "hy.example.com",
		},
		Obfs: &config.ObfsConfig{
			Type:     "salamander",
			Password: "obfs-pw",
		},
		Masq: &config.MasqueradeConfig{
			Type:        "proxy",
			URL:         "https://hy.example.com",
			RewriteHost: true,
		},
		Users: []config.InboundUser{{Name: "charlie"}},
	}

	creds := InboundCredentials{
		Users: map[string]UserCreds{
			"charlie": {Password: "pw-charlie"},
		},
	}

	inbound, err := BuildInbound(in, creds)
	if err != nil {
		t.Fatalf("BuildInbound: %v", err)
	}

	if inbound.Tag != "hy2-in" {
		t.Errorf("Tag = %q, want hy2-in", inbound.Tag)
	}
	if inbound.Type != "hysteria2" {
		t.Errorf("Type = %q, want hysteria2", inbound.Type)
	}

	opts, ok := inbound.Options.(*hysteria2InboundOptions)
	if !ok {
		t.Fatalf("Options type = %T, want *hysteria2InboundOptions", inbound.Options)
	}
	if opts.UpMbps != 1000 {
		t.Errorf("UpMbps = %d, want 1000", opts.UpMbps)
	}
	if opts.DownMbps != 1000 {
		t.Errorf("DownMbps = %d, want 1000", opts.DownMbps)
	}
	if len(opts.Users) != 1 || opts.Users[0].Password != "pw-charlie" {
		t.Errorf("Users = %+v, want [{charlie pw-charlie}]", opts.Users)
	}

	if opts.Obfs == nil {
		t.Fatal("Obfs is nil")
	}
	if opts.Obfs.Type != "salamander" {
		t.Errorf("Obfs.Type = %q, want salamander", opts.Obfs.Type)
	}

	if opts.TLS == nil {
		t.Fatal("TLS is nil")
	}
	if opts.TLS.ServerName != "hy.example.com" {
		t.Errorf("TLS.ServerName = %q, want hy.example.com", opts.TLS.ServerName)
	}
	if opts.TLS.CertificatePath != "certs/hy.example.com.crt" {
		t.Errorf("TLS.CertificatePath = %q, want certs/hy.example.com.crt", opts.TLS.CertificatePath)
	}
	if opts.TLS.KeyPath != "certs/hy.example.com.key" {
		t.Errorf("TLS.KeyPath = %q, want certs/hy.example.com.key", opts.TLS.KeyPath)
	}

	if opts.Masquerade == nil {
		t.Fatal("Masquerade is nil")
	}
	if opts.Masquerade.Type != "proxy" {
		t.Errorf("Masquerade.Type = %q, want proxy", opts.Masquerade.Type)
	}
	if opts.Masquerade.ProxyOptions.URL != "https://hy.example.com" {
		t.Errorf("Masquerade.ProxyOptions.URL = %q, want https://hy.example.com", opts.Masquerade.ProxyOptions.URL)
	}
	if !opts.Masquerade.ProxyOptions.RewriteHost {
		t.Error("Masquerade.ProxyOptions.RewriteHost = false, want true")
	}
}

func TestBuildHysteria2InboundMinimal(t *testing.T) {
	t.Parallel()

	in := config.Inbound{
		Tag:        "hy2-min",
		Type:       "hysteria2",
		ListenPort: 8443,
	}

	inbound, err := BuildInbound(in, InboundCredentials{})
	if err != nil {
		t.Fatalf("BuildInbound: %v", err)
	}

	opts := inbound.Options.(*hysteria2InboundOptions)
	if opts.Obfs != nil {
		t.Error("Obfs should be nil when not configured")
	}
	if opts.Masquerade != nil {
		t.Error("Masquerade should be nil when not configured")
	}
	if opts.TLS != nil {
		t.Error("TLS should be nil when not configured")
	}
}

func TestBuildTunInbound(t *testing.T) {
	t.Parallel()

	in := config.Inbound{
		Tag:                 "tun-in",
		Type:                "tun",
		InterfaceName:       "sing-box",
		Address:             []string{"172.19.0.1/30"},
		MTU:                 1500,
		AutoRoute:           true,
		Stack:               "system",
		ExcludeInterface:    []string{"wt0"},
		RouteExcludeAddress: []string{"10.0.0.0/8"},
	}

	inbound, err := BuildInbound(in, InboundCredentials{})
	if err != nil {
		t.Fatalf("BuildInbound: %v", err)
	}

	if inbound.Tag != "tun-in" {
		t.Errorf("Tag = %q, want tun-in", inbound.Tag)
	}
	if inbound.Type != "tun" {
		t.Errorf("Type = %q, want tun", inbound.Type)
	}

	opts, ok := inbound.Options.(*tunInboundOptions)
	if !ok {
		t.Fatalf("Options type = %T, want *tunInboundOptions", inbound.Options)
	}
	if opts.InterfaceName != "sing-box" {
		t.Errorf("InterfaceName = %q, want sing-box", opts.InterfaceName)
	}
	if len(opts.Address) != 1 {
		t.Fatalf("Address count = %d, want 1", len(opts.Address))
	}
	if opts.Address[0].String() != "172.19.0.1/30" {
		t.Errorf("Address[0] = %s, want 172.19.0.1/30", opts.Address[0])
	}
	if opts.MTU != 1500 {
		t.Errorf("MTU = %d, want 1500", opts.MTU)
	}
	if !opts.AutoRoute {
		t.Error("AutoRoute = false, want true")
	}
	if opts.Stack != "system" {
		t.Errorf("Stack = %q, want system", opts.Stack)
	}
	if len(opts.ExcludeInterface) != 1 || opts.ExcludeInterface[0] != "wt0" {
		t.Errorf("ExcludeInterface = %v, want [wt0]", opts.ExcludeInterface)
	}
	if len(opts.RouteExcludeAddress) != 1 || opts.RouteExcludeAddress[0].String() != "10.0.0.0/8" {
		t.Errorf("RouteExcludeAddress = %v, want [10.0.0.0/8]", opts.RouteExcludeAddress)
	}
}

func TestBuildTunInboundMultipleAddresses(t *testing.T) {
	t.Parallel()

	in := config.Inbound{
		Tag:     "tun-multi",
		Type:    "tun",
		Address: []string{"172.19.0.1/30", "fd00::1/126"},
	}

	inbound, err := BuildInbound(in, InboundCredentials{})
	if err != nil {
		t.Fatalf("BuildInbound: %v", err)
	}

	opts := inbound.Options.(*tunInboundOptions)
	if len(opts.Address) != 2 {
		t.Fatalf("Address count = %d, want 2", len(opts.Address))
	}
}

func TestBuildInboundUnknownType(t *testing.T) {
	t.Parallel()

	in := config.Inbound{Tag: "unknown", Type: "wireguard"}
	_, err := BuildInbound(in, InboundCredentials{})
	if err == nil {
		t.Fatal("expected error for unknown inbound type")
	}

	wantMsg := "unknown inbound type"
	if got := err.Error(); got != fmt.Sprintf("%s: wireguard", wantMsg) {
		t.Errorf("error = %q, want %q", got, fmt.Sprintf("%s: wireguard", wantMsg))
	}
}

func TestBuildVLESSInboundMissingUserCreds(t *testing.T) {
	t.Parallel()

	in := config.Inbound{
		Tag:        "vless-missing",
		Type:       "vless",
		ListenPort: 443,
		Users:      []config.InboundUser{{Name: "alice"}},
	}

	_, err := BuildInbound(in, InboundCredentials{
		Users: map[string]UserCreds{},
	})
	if err == nil {
		t.Fatal("expected error for missing user credentials")
	}

	wantMsg := "missing credentials for declared users"
	if got := err.Error(); !strings.Contains(got, wantMsg) {
		t.Errorf("error = %q, want containing %q", got, wantMsg)
	}
}

func TestBuildHysteria2InboundInvalidAddress(t *testing.T) {
	t.Parallel()

	in := config.Inbound{
		Tag:     "tun-bad-addr",
		Type:    "tun",
		Address: []string{"not-a-cidr"},
	}

	_, err := BuildInbound(in, InboundCredentials{})
	if err == nil {
		t.Fatal("expected error for invalid address")
	}

	wantMsg := "parse address"
	if got := err.Error(); !strings.Contains(got, wantMsg) {
		t.Errorf("error = %q, want containing %q", got, wantMsg)
	}
}

func TestBuildHysteria2InboundInvalidRouteExcludeAddress(t *testing.T) {
	t.Parallel()

	in := config.Inbound{
		Tag:                 "tun-bad-route",
		Type:                "tun",
		RouteExcludeAddress: []string{"999.999.999.999/8"},
	}

	_, err := BuildInbound(in, InboundCredentials{})
	if err == nil {
		t.Fatal("expected error for invalid route exclude address")
	}

	wantMsg := "parse route exclude address"
	if got := err.Error(); !strings.Contains(got, wantMsg) {
		t.Errorf("error = %q, want containing %q", got, wantMsg)
	}
}

func TestBuildVLESSInboundPerUserFlow(t *testing.T) {
	t.Parallel()

	in := config.Inbound{
		Tag:        "vless-flow",
		Type:       "vless",
		ListenPort: 443,
		Users: []config.InboundUser{
			{Name: "desktop", Flow: "xtls-rprx-vision"},
			{Name: "phone"},
		},
	}

	creds := InboundCredentials{
		Users: map[string]UserCreds{
			"desktop": {UUID: "uuid-desktop", Flow: "xtls-rprx-vision"},
			"phone":   {UUID: "uuid-phone"},
		},
	}

	inbound, err := BuildInbound(in, creds)
	if err != nil {
		t.Fatalf("BuildInbound: %v", err)
	}

	opts := inbound.Options.(*vlessInboundOptions)
	if len(opts.Users) != 2 {
		t.Fatalf("Users count = %d, want 2", len(opts.Users))
	}

	usersByName := make(map[string]option.VLESSUser, len(opts.Users))
	for _, u := range opts.Users {
		usersByName[u.Name] = u
	}
	if usersByName["desktop"].Flow != "xtls-rprx-vision" {
		t.Errorf("desktop Flow = %q, want xtls-rprx-vision", usersByName["desktop"].Flow)
	}
	if usersByName["phone"].Flow != "" {
		t.Errorf("phone Flow = %q, want empty", usersByName["phone"].Flow)
	}
}

func TestBuildVLESSInboundListenAddress(t *testing.T) {
	t.Parallel()

	in := config.Inbound{
		Tag:        "vless-listen",
		Type:       "vless",
		Listen:     "::",
		ListenPort: 443,
		Users:      []config.InboundUser{{Name: "alice"}},
	}

	creds := InboundCredentials{
		Users: map[string]UserCreds{"alice": {UUID: "uuid-alice"}},
	}

	inbound, err := BuildInbound(in, creds)
	if err != nil {
		t.Fatalf("BuildInbound: %v", err)
	}

	opts := inbound.Options.(*vlessInboundOptions)
	if opts.Listen == nil {
		t.Fatal("Listen is nil, want non-nil")
	}
	if netip.Addr(*opts.Listen).String() != "::" {
		t.Errorf("Listen = %q, want ::", netip.Addr(*opts.Listen).String())
	}
}

func TestBuildVLESSInboundNoListen(t *testing.T) {
	t.Parallel()

	in := config.Inbound{
		Tag:        "vless-nolisten",
		Type:       "vless",
		ListenPort: 443,
		Users:      []config.InboundUser{{Name: "alice"}},
	}

	creds := InboundCredentials{
		Users: map[string]UserCreds{"alice": {UUID: "uuid-alice"}},
	}

	inbound, err := BuildInbound(in, creds)
	if err != nil {
		t.Fatalf("BuildInbound: %v", err)
	}

	opts := inbound.Options.(*vlessInboundOptions)
	if opts.Listen != nil {
		t.Errorf("Listen = %v, want nil", opts.Listen)
	}
}

func TestBuildHysteria2InboundALPN(t *testing.T) {
	t.Parallel()

	in := config.Inbound{
		Tag:        "hy2-alpn",
		Type:       "hysteria2",
		ListenPort: 443,
		TLS: &config.InboundTLS{
			ServerName: "hy.example.com",
			ALPN:       []string{"h3"},
		},
		Users: []config.InboundUser{{Name: "alice"}},
	}

	creds := InboundCredentials{
		Users: map[string]UserCreds{"alice": {Password: "pw"}},
	}

	inbound, err := BuildInbound(in, creds)
	if err != nil {
		t.Fatalf("BuildInbound: %v", err)
	}

	opts := inbound.Options.(*hysteria2InboundOptions)
	if opts.TLS == nil {
		t.Fatal("TLS is nil")
	}
	if len(opts.TLS.ALPN) != 1 || opts.TLS.ALPN[0] != "h3" {
		t.Errorf("ALPN = %v, want [h3]", opts.TLS.ALPN)
	}
	if opts.TLS.CertificatePath != "certs/hy.example.com.crt" {
		t.Errorf("CertificatePath = %q, want certs/hy.example.com.crt", opts.TLS.CertificatePath)
	}
	if opts.TLS.KeyPath != "certs/hy.example.com.key" {
		t.Errorf("KeyPath = %q, want certs/hy.example.com.key", opts.TLS.KeyPath)
	}
}
