package generate

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/Arsolitt/amnezigo"
	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	singjson "github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/json/badoption"

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

// deterministicPeerIterations runs the peer-list builder enough times that an
// unsorted (map-order) implementation would almost certainly reshuffle at least
// once. Go randomizes map iteration start per range.
const deterministicPeerIterations = 100

// TestAmneziaWGPeerOrderDeterministic proves the server WireGuard peer list is
// emitted in sorted map-key (user name) order on every call, so re-running
// generate produces byte-identical peer blocks (the map-iteration fix). A
// hand-built registry with out-of-order names and distinct PublicKeys pins each
// output position to a specific user.
func TestAmneziaWGPeerOrderDeterministic(t *testing.T) {
	t.Parallel()

	peers := map[string]AmneziaWGPeerCreds{
		"zoe":   {PublicKey: "pub-zoe"},
		"alice": {PublicKey: "pub-alice"},
		"mike":  {PublicKey: "pub-mike"},
		"bob":   {PublicKey: "pub-bob"},
		"diana": {PublicKey: "pub-diana"},
	}
	wantOrder := []string{"alice", "bob", "diana", "mike", "zoe"}

	var reference []byte
	for range deterministicPeerIterations {
		got := buildServerWGPeers(peers)
		if len(got) != len(wantOrder) {
			t.Fatalf("peer count = %d, want %d", len(got), len(wantOrder))
		}
		for i, p := range got {
			want := "pub-" + wantOrder[i]
			if p.PublicKey != want {
				t.Fatalf("peer[%d] PublicKey = %q, want %q (name %q)",
					i, p.PublicKey, want, wantOrder[i])
			}
		}

		b, err := json.Marshal(got)
		if err != nil {
			t.Fatalf("marshal peers: %v", err)
		}
		if reference == nil {
			reference = b
			continue
		}
		if !bytes.Equal(reference, b) {
			t.Fatalf("peer order is non-deterministic across iterations:\n%s\n%s", reference, b)
		}
	}
}

// TestAmneziaWGPresetProducesPresetParams proves that a named preset yields
// deterministic shared amnezia params matching
// amnezigo.GetPreset(name).ToServerObfuscation(): the default (2.0) case maps
// Jc/Jmin/Jmax/S1-S4/H1-H4 only, the 3.1 case additionally maps the preset's
// ContentPadding, generates a header-protection key and applies the mirrored
// range defaults. Both cases omit client-only I1-I5 and construct a valid
// sing-box instance.
func TestAmneziaWGPresetProducesPresetParams(t *testing.T) {
	t.Parallel()

	const presetName = "home-balanced"

	preset, err := amnezigo.GetPreset(presetName)
	if err != nil {
		t.Fatalf("GetPreset(%q): %v", presetName, err)
	}
	expected := preset.ToServerObfuscation()

	buildServer := func(t *testing.T, version string) ([]byte, *option.WireGuardEndpointOptions) {
		t.Helper()

		projectRoot := t.TempDir()

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
					Amnezia:    &config.AmneziaConfig{Preset: presetName, Protocol: "quic", Version: version},
				},
			},
			Outbounds: []config.Outbound{
				{Type: TypeDirect, Tag: "direct"},
			},
			Route: &config.Route{Final: "direct", AutoDetectInterface: true},
		})

		results, err := GenerateAll(projectRoot, "lib", GenerateConfig{})
		if err != nil {
			t.Fatalf("GenerateAll: %v", err)
		}

		serverResult := findResultByName(results, "awg-server")
		if serverResult == nil {
			t.Fatal("awg-server result not found")
		}
		serverConfig := findFile(serverResult.Files, "config.json")
		if serverConfig == nil {
			t.Fatal("awg-server config.json not found")
		}

		opts := parseBoxOptions(t, serverConfig.Content)
		ep := findWGEndpoint(opts, "awg-in")
		if ep == nil {
			t.Fatal("awg-server has no wireguard endpoint tagged awg-in")
		}
		if ep.Amnezia == nil {
			t.Fatal("awg-server endpoint has no amnezia block")
		}
		return serverConfig.Content, ep
	}

	t.Run("default_version_2_0", func(t *testing.T) {
		t.Parallel()
		content, ep := buildServer(t, "")
		assertPresetScalars20(t, ep, expected)

		// Generated config must be a valid sing-box instance.
		t.Run("box_check", func(t *testing.T) {
			t.Parallel()
			singBoxValidate(t, content)
		})
	})

	t.Run("version_3_1", func(t *testing.T) {
		t.Parallel()
		content, ep := buildServer(t, "3.1")
		assertPresetTransport31(t, ep, preset)

		// Generated config must be a valid sing-box instance.
		t.Run("box_check", func(t *testing.T) {
			t.Parallel()
			singBoxValidate(t, content)
		})
	})
}

// assertPresetScalars20 asserts a default-version (2.0) preset block: the
// preset scalars and H ranges map and none of the 3.x keys appear.
func assertPresetScalars20(
	t *testing.T,
	ep *option.WireGuardEndpointOptions,
	expected amnezigo.ServerObfuscationConfig,
) {
	t.Helper()

	if ep.Amnezia.JC != expected.Jc {
		t.Errorf("amnezia JC = %d, want preset Jc %d", ep.Amnezia.JC, expected.Jc)
	}
	if ep.Amnezia.JMin != expected.Jmin {
		t.Errorf("amnezia JMin = %d, want preset Jmin %d", ep.Amnezia.JMin, expected.Jmin)
	}
	if ep.Amnezia.JMax != expected.Jmax {
		t.Errorf("amnezia JMax = %d, want preset Jmax %d", ep.Amnezia.JMax, expected.Jmax)
	}
	if ep.Amnezia.S1 != expected.S1 {
		t.Errorf("amnezia S1 = %d, want preset S1 %d", ep.Amnezia.S1, expected.S1)
	}
	if ep.Amnezia.S2 != expected.S2 {
		t.Errorf("amnezia S2 = %d, want preset S2 %d", ep.Amnezia.S2, expected.S2)
	}
	if ep.Amnezia.S3 != expected.S3 {
		t.Errorf("amnezia S3 = %d, want preset S3 %d", ep.Amnezia.S3, expected.S3)
	}
	if ep.Amnezia.S4 != expected.S4 {
		t.Errorf("amnezia S4 = %d, want preset S4 %d", ep.Amnezia.S4, expected.S4)
	}
	assertAmneziaHeaderRange(t, "amnezia H1", ep.Amnezia.H1, expected.H1)
	assertAmneziaHeaderRange(t, "amnezia H2", ep.Amnezia.H2, expected.H2)
	assertAmneziaHeaderRange(t, "amnezia H3", ep.Amnezia.H3, expected.H3)
	assertAmneziaHeaderRange(t, "amnezia H4", ep.Amnezia.H4, expected.H4)

	// A 2.0 block must carry none of the 3.x keys.
	if ep.Amnezia.HeaderProtectionKey != "" {
		t.Errorf("2.0 block must not carry a header protection key, got %q", ep.Amnezia.HeaderProtectionKey)
	}
	for name, r := range map[string]*badoption.Range[uint32]{
		"ContentPaddingAddition": ep.Amnezia.ContentPaddingAddition,
		"RekeyAfterTime":         ep.Amnezia.RekeyAfterTime,
		"RekeyTimeout":           ep.Amnezia.RekeyTimeout,
		"RejectAfterTime":        ep.Amnezia.RejectAfterTime,
		"KeepaliveTimeout":       ep.Amnezia.KeepaliveTimeout,
		"MaxHandshakeAttempts":   ep.Amnezia.MaxHandshakeAttempts,
	} {
		if r != nil {
			t.Errorf("2.0 block must not carry %s, got %v", name, r)
		}
	}

	// Server amnezia must NOT carry I1-I5 (client-only).
	if ep.Amnezia.I1 != "" {
		t.Errorf("server amnezia must not carry I1, got %q", ep.Amnezia.I1)
	}
}

// assertPresetTransport31 asserts a 3.1 preset block: the preset's
// ContentPadding maps verbatim, the header-protection key is 44-char base64 of
// 32 bytes, the five timer ranges fall back to the mirrored defaults, and every
// S-prefix meets the nonce floor.
func assertPresetTransport31(t *testing.T, ep *option.WireGuardEndpointOptions, preset amnezigo.Preset) {
	t.Helper()

	if ep.Amnezia.ContentPaddingAddition == nil ||
		ep.Amnezia.ContentPaddingAddition.From != uint32(preset.ContentPadding.Min) ||
		ep.Amnezia.ContentPaddingAddition.To != uint32(preset.ContentPadding.Max) {
		t.Errorf(
			"ContentPaddingAddition = %v, want %d-%d",
			ep.Amnezia.ContentPaddingAddition,
			preset.ContentPadding.Min,
			preset.ContentPadding.Max,
		)
	}

	hpk := ep.Amnezia.HeaderProtectionKey
	if len(hpk) != 44 {
		t.Errorf("header protection key length = %d, want 44", len(hpk))
	}
	if raw, err := base64.StdEncoding.DecodeString(hpk); err != nil || len(raw) != 32 {
		t.Errorf("header protection key must be base64 of 32 bytes, got %q (err %v)", hpk, err)
	}

	for name, check := range map[string]struct {
		got      *badoption.Range[uint32]
		from, to uint32
	}{
		"RekeyAfterTime":       {ep.Amnezia.RekeyAfterTime, 120, 180},
		"RekeyTimeout":         {ep.Amnezia.RekeyTimeout, 5, 8},
		"RejectAfterTime":      {ep.Amnezia.RejectAfterTime, 180, 240},
		"KeepaliveTimeout":     {ep.Amnezia.KeepaliveTimeout, 8, 12},
		"MaxHandshakeAttempts": {ep.Amnezia.MaxHandshakeAttempts, 16, 20},
	} {
		if check.got == nil || check.got.From != check.from || check.got.To != check.to {
			t.Errorf("%s = %v, want %d-%d", name, check.got, check.from, check.to)
		}
	}

	for i, s := range [4]int{ep.Amnezia.S1, ep.Amnezia.S2, ep.Amnezia.S3, ep.Amnezia.S4} {
		if s < 12 {
			t.Errorf("S%d = %d, want >= 12 under header protection", i+1, s)
		}
	}
}

// assertAmneziaHeaderRange asserts one header range pointer against an amnezigo
// HeaderRange.
func assertAmneziaHeaderRange(t *testing.T, name string, got *badoption.Range[uint32], want amnezigo.HeaderRange) {
	t.Helper()
	if got == nil || got.From != want.Min || got.To != want.Max {
		t.Errorf("%s = %v, want %d-%d", name, got, want.Min, want.Max)
	}
}

// TestResolveServerAmneziaVersionLifecycle covers the persisted-block version
// gate: a persisted block wins verbatim only when its transport-protection
// state matches the requested version (persistedHasTP == wantTP); on a
// mismatch the whole block is regenerated for the requested version.
func TestResolveServerAmneziaVersionLifecycle(t *testing.T) {
	t.Parallel()

	const tag = "awg-in"

	persistedWith := func(block *option.WireGuardAmnezia) config.PersistedCredentials {
		return config.PersistedCredentials{
			WireGuardEndpoints: map[string]config.WireGuardEndpointCreds{
				tag: {Amnezia: block},
			},
		}
	}

	block20 := &option.WireGuardAmnezia{
		JC:   7,
		JMin: 300,
		JMax: 1100,
		S1:   30,
		S2:   35,
		S3:   20,
		S4:   12,
		H1:   &badoption.Range[uint32]{From: 50, To: 50000000},
	}
	block3x := &option.WireGuardAmnezia{
		JC:                  7,
		JMin:                300,
		JMax:                1100,
		S1:                  30,
		S2:                  35,
		S3:                  20,
		S4:                  12,
		H1:                  &badoption.Range[uint32]{From: 1, To: 1},
		HeaderProtectionKey: "c2VudGluZWxrZXk=",
	}

	assertNoTransportRanges := func(t *testing.T, block option.WireGuardAmnezia) {
		t.Helper()
		if block.HeaderProtectionKey != "" {
			t.Errorf("block must not carry a header protection key, got %q", block.HeaderProtectionKey)
		}
		for name, r := range map[string]*badoption.Range[uint32]{
			"ContentPaddingAddition": block.ContentPaddingAddition,
			"RekeyAfterTime":         block.RekeyAfterTime,
			"RekeyTimeout":           block.RekeyTimeout,
			"RejectAfterTime":        block.RejectAfterTime,
			"KeepaliveTimeout":       block.KeepaliveTimeout,
			"MaxHandshakeAttempts":   block.MaxHandshakeAttempts,
		} {
			if r != nil {
				t.Errorf("block must not carry %s, got %v", name, r)
			}
		}
	}

	t.Run("fresh_default_has_no_3x_fields", func(t *testing.T) {
		t.Parallel()
		block, err := resolveServerAmnezia(tag, &config.AmneziaConfig{}, config.PersistedCredentials{})
		if err != nil {
			t.Fatalf("resolveServerAmnezia: %v", err)
		}
		assertNoTransportRanges(t, block)
		if block.H1 == nil || block.H4 == nil {
			t.Error("fresh 2.0 block must carry random H1-H4 ranges")
		}
	})

	t.Run("persisted_2_0_default_verbatim", func(t *testing.T) {
		t.Parallel()
		block, err := resolveServerAmnezia(tag, &config.AmneziaConfig{}, persistedWith(block20))
		if err != nil {
			t.Fatalf("resolveServerAmnezia: %v", err)
		}
		if !reflect.DeepEqual(block, *block20) {
			t.Errorf("block = %+v, want verbatim reuse of %+v", block, *block20)
		}
	})

	t.Run("persisted_2_0_request_3_1_regenerates", func(t *testing.T) {
		t.Parallel()
		block, err := resolveServerAmnezia(
			tag, &config.AmneziaConfig{Version: "3.1"}, persistedWith(block20),
		)
		if err != nil {
			t.Fatalf("resolveServerAmnezia: %v", err)
		}
		if block.HeaderProtectionKey == "" {
			t.Error("regenerated 3.1 block must carry a header protection key")
		}
		for i, s := range [4]int{block.S1, block.S2, block.S3, block.S4} {
			if s < 12 {
				t.Errorf("S%d = %d, want >= 12 under header protection", i+1, s)
			}
		}
		// The random 3.x path collapses H1-H4 to the standard 1..4 ranges.
		for i, got := range [4]*badoption.Range[uint32]{block.H1, block.H2, block.H3, block.H4} {
			if got == nil || got.From != uint32(i+1) || got.To != uint32(i+1) {
				t.Errorf("H%d = %v, want %d-%d", i+1, got, i+1, i+1)
			}
		}
	})

	t.Run("persisted_3_x_request_3_1_verbatim", func(t *testing.T) {
		t.Parallel()
		block, err := resolveServerAmnezia(
			tag, &config.AmneziaConfig{Version: "3.1"}, persistedWith(block3x),
		)
		if err != nil {
			t.Fatalf("resolveServerAmnezia: %v", err)
		}
		if !reflect.DeepEqual(block, *block3x) {
			t.Errorf("block = %+v, want verbatim reuse of %+v", block, *block3x)
		}
	})

	t.Run("persisted_3_x_default_regenerates_2_0", func(t *testing.T) {
		t.Parallel()
		block, err := resolveServerAmnezia(tag, &config.AmneziaConfig{}, persistedWith(block3x))
		if err != nil {
			t.Fatalf("resolveServerAmnezia: %v", err)
		}
		assertNoTransportRanges(t, block)
		if block.HeaderProtectionKey == block3x.HeaderProtectionKey {
			t.Error("regenerated 2.0 block must not reuse the persisted 3.x key")
		}
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
