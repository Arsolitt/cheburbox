package generate

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Arsolitt/amnezigo"
	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	singjson "github.com/sagernet/sing/common/json"

	"github.com/Arsolitt/cheburbox/config"
)

// parseBoxOptions parses marshaled sing-box config.json bytes back into typed
// option.Options using the registry-aware context (so endpoint options resolve).
func parseBoxOptions(t *testing.T, configJSON []byte) option.Options {
	t.Helper()
	ctx := include.Context(context.Background())
	var opts option.Options
	if err := singjson.UnmarshalContext(ctx, configJSON, &opts); err != nil {
		t.Fatalf("parse config.json: %v", err)
	}
	return opts
}

// findWGEndpoint returns the wireguard endpoint options for the given tag, or
// nil if no such endpoint exists.
func findWGEndpoint(opts option.Options, tag string) *option.WireGuardEndpointOptions {
	for _, ep := range opts.Endpoints {
		if ep.Tag != tag {
			continue
		}
		if wg, ok := ep.Options.(*option.WireGuardEndpointOptions); ok {
			return wg
		}
	}
	return nil
}

// singBoxValidate constructs a sing-box instance from the marshaled config.json
// bytes (replicating `sing-box check` / validate phase 2) and closes it
// immediately. Fails the test if construction fails. The check is in-memory:
// these AmneziaWG configs carry no relative file references, so no chdir is
// needed (t.Chdir is also incompatible with t.Parallel).
func singBoxValidate(t *testing.T, configJSON []byte) {
	t.Helper()

	ctx := include.Context(context.Background())
	opts, err := singjson.UnmarshalExtendedContext[box.Options](ctx, configJSON)
	if err != nil {
		t.Fatalf("parse config.json: %v", err)
	}
	opts.Context = ctx

	instance, err := box.New(opts)
	if err != nil {
		// The default test build (go test ./...) does not compile WireGuard or
		// its gVisor dependency (-tags with_wireguard,with_gvisor). When that is
		// the only reason box.New fails, skip rather than fail: the structural
		// assertions elsewhere already validate the generation, and a fully
		// tagged build performs the complete in-process check.
		if strings.Contains(err.Error(), "is not included in this build") {
			t.Skipf("skipping box.New check (rebuild with -tags with_wireguard,with_gvisor): %v", err)
		}
		t.Fatalf("sing-box check (box.New): %v", err)
	}
	_ = instance.Close()
}

// TestAmneziaWGCrossServer verifies the full AmneziaWG cross-server flow: an
// amneziawg inbound on one server becomes a native sing-box wireguard endpoint,
// and a client server's amneziawg outbound becomes a matching client endpoint
// whose peer is provisioned back into the server's peer list.
func TestAmneziaWGCrossServer(t *testing.T) {
	t.Parallel()

	projectRoot := t.TempDir()

	// awg-server: amneziawg inbound + direct outbound.
	setupTestServer(t, projectRoot, "awg-server", config.Config{
		Version:  1,
		Endpoint: "203.0.113.10",
		DNS: config.DNS{
			Final:   new("dns-local"),
			Servers: []config.DNSServer{{Type: "local", Tag: "dns-local"}},
		},
		Inbounds: []config.Inbound{
			{
				Tag:        "awg-in",
				Type:       TypeAmneziaWG,
				ListenPort: 51820,
				Address:    []string{"10.7.0.1/24"},
				Amnezia:    &config.AmneziaConfig{Protocol: "quic", MTU: 1280},
			},
		},
		Outbounds: []config.Outbound{
			{Type: TypeDirect, Tag: "direct"},
		},
		Route: &config.Route{Final: "direct", AutoDetectInterface: true},
	})

	// awg-client: tun inbound + amneziawg outbound -> awg-server.
	setupTestServer(t, projectRoot, "awg-client", config.Config{
		Version:  1,
		Endpoint: "198.51.100.5",
		DNS: config.DNS{
			Final:   new("dns-local"),
			Servers: []config.DNSServer{{Type: "local", Tag: "dns-local"}},
		},
		Inbounds: []config.Inbound{
			{
				Tag:           "tun-in",
				Type:          TypeTun,
				InterfaceName: "sing-box",
				Address:       []string{"172.19.0.1/30"},
				MTU:           1500,
				AutoRoute:     true,
				Stack:         "system",
			},
		},
		Outbounds: []config.Outbound{
			{Type: TypeDirect, Tag: "direct"},
			{
				Type:    TypeAmneziaWG,
				Tag:     "awg-out",
				Server:  "awg-server",
				Inbound: "awg-in",
				Address: []string{"10.7.0.2/32"},
			},
		},
		Route: &config.Route{Final: "awg-out", AutoDetectInterface: true},
	})

	results, err := GenerateAll(projectRoot, "lib", GenerateConfig{})
	if err != nil {
		t.Fatalf("GenerateAll: %v", err)
	}

	serverResult := findResultByName(results, "awg-server")
	if serverResult == nil {
		t.Fatal("awg-server result not found")
	}
	clientResult := findResultByName(results, "awg-client")
	if clientResult == nil {
		t.Fatal("awg-client result not found")
	}

	serverConfig := findFile(serverResult.Files, "config.json")
	if serverConfig == nil {
		t.Fatal("awg-server config.json not found")
	}
	clientConfig := findFile(clientResult.Files, "config.json")
	if clientConfig == nil {
		t.Fatal("awg-client config.json not found")
	}

	serverOpts := parseBoxOptions(t, serverConfig.Content)
	clientOpts := parseBoxOptions(t, clientConfig.Content)

	serverEP := findWGEndpoint(serverOpts, "awg-in")
	if serverEP == nil {
		t.Fatal("awg-server has no wireguard endpoint tagged awg-in")
	}
	if serverEP.Amnezia == nil {
		t.Fatal("awg-server endpoint has no amnezia block")
	}

	clientEP := findWGEndpoint(clientOpts, "awg-out")
	if clientEP == nil {
		t.Fatal("awg-client has no wireguard endpoint tagged awg-out")
	}
	if clientEP.Amnezia == nil {
		t.Fatal("awg-client endpoint has no amnezia block")
	}

	// Client peer PublicKey must equal the server's public key (derived from
	// the server endpoint's private key).
	serverPub := amnezigo.DerivePublicKey(serverEP.PrivateKey)
	if len(clientEP.Peers) != 1 {
		t.Fatalf("expected exactly 1 client peer, got %d", len(clientEP.Peers))
	}
	if clientEP.Peers[0].PublicKey != serverPub {
		t.Errorf("client peer PublicKey = %q, want server public %q",
			clientEP.Peers[0].PublicKey, serverPub)
	}

	// Shared amnezia params (JC/S1/H1) must be identical on both ends.
	if clientEP.Amnezia.JC != serverEP.Amnezia.JC {
		t.Errorf("amnezia JC mismatch: client=%d server=%d",
			clientEP.Amnezia.JC, serverEP.Amnezia.JC)
	}
	if clientEP.Amnezia.S1 != serverEP.Amnezia.S1 {
		t.Errorf("amnezia S1 mismatch: client=%d server=%d",
			clientEP.Amnezia.S1, serverEP.Amnezia.S1)
	}
	if !rangeEqual(clientEP.Amnezia.H1, serverEP.Amnezia.H1) {
		t.Errorf("amnezia H1 mismatch: client=%v server=%v",
			clientEP.Amnezia.H1, serverEP.Amnezia.H1)
	}

	// Client amnezia must carry I1-I5; server amnezia must NOT.
	if clientEP.Amnezia.I1 == "" {
		t.Error("client amnezia is missing I1 (expected client-only I1-I5)")
	}
	if serverEP.Amnezia.I1 != "" {
		t.Errorf("server amnezia must not carry I1, got %q", serverEP.Amnezia.I1)
	}

	// Server peer list must include a peer whose PublicKey equals the client's
	// derived public key.
	clientPub := amnezigo.DerivePublicKey(clientEP.PrivateKey)
	if !serverHasPeer(serverEP, clientPub) {
		t.Errorf("server endpoint has no peer with client public key %q", clientPub)
	}

	// Both configs must construct a valid sing-box instance (box.New). This is
	// the strongest validation; under the default test build (no
	// -tags with_wireguard) the WireGuard endpoint can't be constructed and
	// the subtest is skipped — the structural assertions above still fully
	// exercise the generation logic.
	t.Run("box_check_server", func(t *testing.T) {
		t.Parallel()
		singBoxValidate(t, serverConfig.Content)
	})
	t.Run("box_check_client", func(t *testing.T) {
		t.Parallel()
		singBoxValidate(t, clientConfig.Content)
	})
}

// TestAmneziaWGPersistenceStable verifies that running GenerateAll twice
// produces identical server/amnezia/client key material: the second run reuses
// the persisted server private key, shared amnezia params, and client private
// key rather than regenerating them.
func TestAmneziaWGPersistenceStable(t *testing.T) {
	t.Parallel()

	projectRoot := t.TempDir()

	awgServerCfg := config.Config{
		Version:  1,
		Endpoint: "203.0.113.10",
		DNS: config.DNS{
			Final:   new("dns-local"),
			Servers: []config.DNSServer{{Type: "local", Tag: "dns-local"}},
		},
		Inbounds: []config.Inbound{
			{
				Tag:        "awg-in",
				Type:       TypeAmneziaWG,
				ListenPort: 51820,
				Address:    []string{"10.7.0.1/24"},
				Amnezia:    &config.AmneziaConfig{Protocol: "quic", MTU: 1280},
			},
		},
		Outbounds: []config.Outbound{
			{Type: TypeDirect, Tag: "direct"},
		},
		Route: &config.Route{Final: "direct", AutoDetectInterface: true},
	}
	awgClientCfg := config.Config{
		Version:  1,
		Endpoint: "198.51.100.5",
		DNS: config.DNS{
			Final:   new("dns-local"),
			Servers: []config.DNSServer{{Type: "local", Tag: "dns-local"}},
		},
		Outbounds: []config.Outbound{
			{Type: TypeDirect, Tag: "direct"},
			{
				Type:    TypeAmneziaWG,
				Tag:     "awg-out",
				Server:  "awg-server",
				Inbound: "awg-in",
				Address: []string{"10.7.0.2/32"},
			},
		},
		Route: &config.Route{Final: "awg-out", AutoDetectInterface: true},
	}

	setupTestServer(t, projectRoot, "awg-server", awgServerCfg)
	setupTestServer(t, projectRoot, "awg-client", awgClientCfg)

	// Run 1: generate everything fresh.
	run1, err := GenerateAll(projectRoot, "lib", GenerateConfig{})
	if err != nil {
		t.Fatalf("GenerateAll run 1: %v", err)
	}
	run1Server := findResultByName(run1, "awg-server")
	run1Client := findResultByName(run1, "awg-client")
	if run1Server == nil || run1Client == nil {
		t.Fatal("run 1 missing awg-server or awg-client result")
	}

	// Persist run 1's config.json to disk so run 2 can load persisted creds.
	if err := os.WriteFile(
		filepath.Join(projectRoot, "awg-server", "config.json"),
		findFile(run1Server.Files, "config.json").Content, 0o644); err != nil {
		t.Fatalf("write awg-server config.json: %v", err)
	}
	if err := os.WriteFile(
		filepath.Join(projectRoot, "awg-client", "config.json"),
		findFile(run1Client.Files, "config.json").Content, 0o644); err != nil {
		t.Fatalf("write awg-client config.json: %v", err)
	}

	// Run 2: should reuse persisted key material.
	run2, err := GenerateAll(projectRoot, "lib", GenerateConfig{})
	if err != nil {
		t.Fatalf("GenerateAll run 2: %v", err)
	}
	run2Server := findResultByName(run2, "awg-server")
	run2Client := findResultByName(run2, "awg-client")
	if run2Server == nil || run2Client == nil {
		t.Fatal("run 2 missing awg-server or awg-client result")
	}

	r1ServerEP := findWGEndpoint(parseBoxOptions(t, findFile(run1Server.Files, "config.json").Content), "awg-in")
	r2ServerEP := findWGEndpoint(parseBoxOptions(t, findFile(run2Server.Files, "config.json").Content), "awg-in")
	r1ClientEP := findWGEndpoint(parseBoxOptions(t, findFile(run1Client.Files, "config.json").Content), "awg-out")
	r2ClientEP := findWGEndpoint(parseBoxOptions(t, findFile(run2Client.Files, "config.json").Content), "awg-out")

	if r1ServerEP == nil || r2ServerEP == nil || r1ClientEP == nil || r2ClientEP == nil {
		t.Fatal("an endpoint was missing across runs")
	}

	// Server private key stable.
	if r1ServerEP.PrivateKey != r2ServerEP.PrivateKey {
		t.Errorf("server private key changed across runs: %q -> %q",
			r1ServerEP.PrivateKey, r2ServerEP.PrivateKey)
	}
	// Shared amnezia stable (server side).
	if r1ServerEP.Amnezia.JC != r2ServerEP.Amnezia.JC ||
		r1ServerEP.Amnezia.S1 != r2ServerEP.Amnezia.S1 ||
		!rangeEqual(r1ServerEP.Amnezia.H1, r2ServerEP.Amnezia.H1) {
		t.Errorf("server amnezia changed across runs: run1=%+v run2=%+v",
			r1ServerEP.Amnezia, r2ServerEP.Amnezia)
	}
	// Client private key stable.
	if r1ClientEP.PrivateKey != r2ClientEP.PrivateKey {
		t.Errorf("client private key changed across runs: %q -> %q",
			r1ClientEP.PrivateKey, r2ClientEP.PrivateKey)
	}

	// The server's peer for this client must still match the client's derived
	// public key after the second run (consistency persisted across runs).
	clientPub := amnezigo.DerivePublicKey(r2ClientEP.PrivateKey)
	if !serverHasPeer(r2ServerEP, clientPub) {
		t.Errorf("run 2 server endpoint has no peer matching client public key %q", clientPub)
	}
}

func rangeEqual[T comparable](a, b *T) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

func serverHasPeer(ep *option.WireGuardEndpointOptions, publicKey string) bool {
	for _, peer := range ep.Peers {
		if peer.PublicKey == publicKey {
			return true
		}
	}
	return false
}
