package config

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	singjson "github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/json/badoption"
)

func TestLoadPersistedCredentialsEmpty(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	creds, err := LoadPersistedCredentials(filepath.Join(dir, "config.json"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(creds.InboundUsers) != 0 {
		t.Errorf("expected empty users, got %d", len(creds.InboundUsers))
	}
}

func TestLoadPersistedCredentialsVLESS(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	configJSON := filepath.Join(dir, "config.json")
	content := `{
		"inbounds": [{
			"type": "vless",
			"tag": "vless-in",
			"listen_port": 443,
			"tls": {
				"enabled": true,
				"reality": {
					"enabled": true,
					"private_key": "privkey123",
					"short_id": ["abcd"],
					"handshake": {"server": "example.com", "server_port": 443}
				}
			},
			"users": [
				{"name": "alice", "uuid": "uuid-alice"},
				{"name": "bob", "uuid": "uuid-bob"}
			]
		}]
	}`
	if err := os.WriteFile(configJSON, []byte(content), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	creds, err := LoadPersistedCredentials(configJSON)
	if err != nil {
		t.Fatalf("load credentials: %v", err)
	}

	if creds.InboundUsers["vless-in"]["alice"].UUID != "uuid-alice" {
		t.Errorf("alice UUID = %q, want %q", creds.InboundUsers["vless-in"]["alice"].UUID, "uuid-alice")
	}
	if creds.InboundUsers["vless-in"]["bob"].UUID != "uuid-bob" {
		t.Errorf("bob UUID = %q, want %q", creds.InboundUsers["vless-in"]["bob"].UUID, "uuid-bob")
	}
	if creds.RealityKeys["vless-in"].PrivateKey != "privkey123" {
		t.Errorf("reality private key = %q, want %q", creds.RealityKeys["vless-in"].PrivateKey, "privkey123")
	}
	if len(creds.RealityKeys["vless-in"].ShortID) != 1 || creds.RealityKeys["vless-in"].ShortID[0] != "abcd" {
		t.Errorf("reality short_id = %v, want [abcd]", creds.RealityKeys["vless-in"].ShortID)
	}
}

func TestLoadPersistedCredentialsHysteria2(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	configJSON := filepath.Join(dir, "config.json")
	content := `{
		"inbounds": [{
			"type": "hysteria2",
			"tag": "hy2-in",
			"listen_port": 443,
			"tls": {"enabled": true, "server_name": "example.com"},
			"obfs": {"type": "salamander", "password": "obfs-pw"},
			"users": [
				{"name": "charlie", "password": "pw-charlie"}
			]
		}]
	}`
	if err := os.WriteFile(configJSON, []byte(content), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	creds, err := LoadPersistedCredentials(configJSON)
	if err != nil {
		t.Fatalf("load credentials: %v", err)
	}

	if creds.InboundUsers["hy2-in"]["charlie"].Password != "pw-charlie" {
		t.Errorf("charlie password = %q, want %q", creds.InboundUsers["hy2-in"]["charlie"].Password, "pw-charlie")
	}
	if creds.ObfsPasswords["hy2-in"] != "obfs-pw" {
		t.Errorf("obfs password = %q, want %q", creds.ObfsPasswords["hy2-in"], "obfs-pw")
	}
}

func TestLoadPersistedCredentialsInvalidJSON(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	configJSON := filepath.Join(dir, "config.json")
	if err := os.WriteFile(configJSON, []byte(`{invalid json}`), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	_, err := LoadPersistedCredentials(configJSON)
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestExtractCredentialsFromOptions(t *testing.T) {
	t.Parallel()

	opts := buildTestOptions()
	creds := ExtractCredentials(opts)

	if len(creds.InboundUsers) != 2 {
		t.Fatalf("expected 2 inbound user maps, got %d", len(creds.InboundUsers))
	}
	if creds.InboundUsers["vless-in"]["alice"].UUID != "test-uuid" {
		t.Errorf("alice UUID = %q, want %q", creds.InboundUsers["vless-in"]["alice"].UUID, "test-uuid")
	}
	if creds.InboundUsers["hy2-in"]["bob"].Password != "test-password" {
		t.Errorf("bob password = %q, want %q", creds.InboundUsers["hy2-in"]["bob"].Password, "test-password")
	}
	if creds.RealityKeys["vless-in"].PrivateKey != "test-privkey" {
		t.Errorf("reality private key = %q, want %q", creds.RealityKeys["vless-in"].PrivateKey, "test-privkey")
	}
	if creds.ObfsPasswords["hy2-in"] != "test-obfs-pw" {
		t.Errorf("obfs password = %q, want %q", creds.ObfsPasswords["hy2-in"], "test-obfs-pw")
	}
}

func buildTestOptions() *option.Options {
	return &option.Options{
		Inbounds: []option.Inbound{
			{
				Type: "vless",
				Tag:  "vless-in",
				Options: &option.VLESSInboundOptions{
					Users: []option.VLESSUser{
						{Name: "alice", UUID: "test-uuid"},
					},
					InboundTLSOptionsContainer: option.InboundTLSOptionsContainer{
						TLS: &option.InboundTLSOptions{
							Enabled: true,
							Reality: &option.InboundRealityOptions{
								Enabled:    true,
								PrivateKey: "test-privkey",
								ShortID:    []string{"test-short-id"},
							},
						},
					},
				},
			},
			{
				Type: "hysteria2",
				Tag:  "hy2-in",
				Options: &option.Hysteria2InboundOptions{
					Users: []option.Hysteria2User{
						{Name: "bob", Password: "test-password"},
					},
					Obfs: &option.Hysteria2Obfs{
						Type:     "salamander",
						Password: "test-obfs-pw",
					},
					InboundTLSOptionsContainer: option.InboundTLSOptionsContainer{
						TLS: &option.InboundTLSOptions{
							Enabled:    true,
							ServerName: "example.com",
						},
					},
				},
			},
		},
	}
}

// Wireguard endpoint credential test fixtures. Numeric literals are kept as
// named constants to satisfy the mnd linter; string literals are inline.
const (
	wgServerTag        = "awg-server"
	wgClientTag        = "awg-client"
	wgPlainTag         = "plain-wg"
	wgServerPrivateKey = "server-private-key"
	wgClientPrivateKey = "client-private-key"
	wgPlainPrivateKey  = "plain-private-key"
	wgServerSubnet     = "10.0.0.1/24"
	wgClientAddr       = "10.0.0.5/32"
	wgClient1Pub       = "client1-public-key"
	wgClient2Pub       = "client2-public-key"
	wgServerPub        = "server-public-key"
	wgPSK1             = "preshared-key-1"
	wgPSK2             = "preshared-key-2"
	wgClientI1         = "client-i1-value"

	wgServerListenPort uint16 = 51820
	wgPlainListenPort  uint16 = 51821
	wgMTU              uint32 = 1280
	wgAmneziaJC               = 10
	wgAmneziaJMin             = 20
	wgAmneziaJMax             = 30
	wgAmneziaS1               = 1
	wgAmneziaS2               = 2
	wgAmneziaS3               = 3
	wgAmneziaS4               = 4
	wgH1From           uint32 = 100
	wgH1To             uint32 = 200
	wgServerPeerCount         = 2
	wgClientPeerCount         = 1
)

func TestExtractWireGuardEndpoints(t *testing.T) {
	t.Parallel()

	parsed := marshalRoundTrip(t, buildWireGuardTestOptions())
	creds := ExtractCredentials(parsed)

	server, ok := creds.WireGuardEndpoints[wgServerTag]
	if !ok {
		t.Fatalf("server endpoint %q not extracted", wgServerTag)
	}
	if server.PrivateKey != wgServerPrivateKey {
		t.Errorf("server PrivateKey = %q, want %q", server.PrivateKey, wgServerPrivateKey)
	}
	if server.Amnezia == nil {
		t.Fatal("server Amnezia is nil")
	}
	if server.Amnezia.JC != wgAmneziaJC {
		t.Errorf("server Amnezia.JC = %d, want %d", server.Amnezia.JC, wgAmneziaJC)
	}
	if server.Amnezia.H1 == nil {
		t.Fatal("server Amnezia.H1 is nil")
	}
	if server.Amnezia.H1.From != wgH1From {
		t.Errorf("server Amnezia.H1.From = %d, want %d", server.Amnezia.H1.From, wgH1From)
	}
	if len(server.Peers) != wgServerPeerCount {
		t.Fatalf("server Peers count = %d, want %d", len(server.Peers), wgServerPeerCount)
	}
	if peer, found := server.Peers[wgClient1Pub]; !found {
		t.Errorf("server Peers missing client1 pubkey %q", wgClient1Pub)
	} else if peer.PresharedKey != wgPSK1 {
		t.Errorf("client1 PresharedKey = %q, want %q", peer.PresharedKey, wgPSK1)
	}
	if _, found := server.Peers[wgClient2Pub]; !found {
		t.Errorf("server Peers missing client2 pubkey %q", wgClient2Pub)
	}

	client, ok := creds.WireGuardEndpoints[wgClientTag]
	if !ok {
		t.Fatalf("client endpoint %q not extracted", wgClientTag)
	}
	if client.PrivateKey != wgClientPrivateKey {
		t.Errorf("client PrivateKey = %q, want %q", client.PrivateKey, wgClientPrivateKey)
	}
	if client.Amnezia == nil {
		t.Fatal("client Amnezia is nil")
	}
	if client.Amnezia.JC != wgAmneziaJC {
		t.Errorf("client Amnezia.JC = %d, want %d", client.Amnezia.JC, wgAmneziaJC)
	}
	if client.Amnezia.H1 == nil || client.Amnezia.H1.From != wgH1From {
		t.Errorf("client Amnezia.H1.From round-trip failed: %+v", client.Amnezia.H1)
	}
	if client.Amnezia.I1 != wgClientI1 {
		t.Errorf("client Amnezia.I1 = %q, want %q", client.Amnezia.I1, wgClientI1)
	}
	if len(client.Peers) != wgClientPeerCount {
		t.Fatalf("client Peers count = %d, want %d", len(client.Peers), wgClientPeerCount)
	}
	if _, found := client.Peers[wgServerPub]; !found {
		t.Errorf("client Peers missing server pubkey %q", wgServerPub)
	}

	if _, found := creds.WireGuardEndpoints[wgPlainTag]; found {
		t.Errorf("plain wireguard endpoint %q must NOT be extracted (nil Amnezia)", wgPlainTag)
	}

	// Deep-clone independence: persisted Amnezia.H1 must not alias the parsed
	// options pointer. Mutating the parsed copy must leave persisted creds stable.
	serverOpts, ok := parsed.Endpoints[0].Options.(*option.WireGuardEndpointOptions)
	if !ok {
		t.Fatalf("parsed server endpoint options assertion failed")
	}
	serverOpts.Amnezia.H1.From = serverOpts.Amnezia.H1.To
	if creds.WireGuardEndpoints[wgServerTag].Amnezia.H1.From != wgH1From {
		t.Errorf("persisted H1.From aliased parsed opts: got %d, want %d",
			creds.WireGuardEndpoints[wgServerTag].Amnezia.H1.From, wgH1From)
	}
}

func TestLoadPersistedCredentialsWireGuard(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	configJSON := filepath.Join(dir, "config.json")
	data, err := singjson.MarshalContext(include.Context(context.Background()), buildWireGuardTestOptions())
	if err != nil {
		t.Fatalf("marshal options: %v", err)
	}
	if err := os.WriteFile(configJSON, data, 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	creds, err := LoadPersistedCredentials(configJSON)
	if err != nil {
		t.Fatalf("load credentials: %v", err)
	}
	if _, ok := creds.WireGuardEndpoints[wgServerTag]; !ok {
		t.Errorf("server endpoint %q not loaded from file", wgServerTag)
	}
	if _, ok := creds.WireGuardEndpoints[wgClientTag]; !ok {
		t.Errorf("client endpoint %q not loaded from file", wgClientTag)
	}
	if _, ok := creds.WireGuardEndpoints[wgPlainTag]; ok {
		t.Errorf("plain wireguard endpoint %q must NOT be loaded from file", wgPlainTag)
	}
}

func buildWireGuardTestOptions() *option.Options {
	return &option.Options{
		Endpoints: []option.Endpoint{
			{
				Type: "wireguard",
				Tag:  wgServerTag,
				Options: &option.WireGuardEndpointOptions{
					Name:       "awg0",
					MTU:        wgMTU,
					Address:    badoption.Listable[netip.Prefix]{netip.MustParsePrefix(wgServerSubnet)},
					PrivateKey: wgServerPrivateKey,
					ListenPort: wgServerListenPort,
					Peers: []option.WireGuardPeer{
						{PublicKey: wgClient1Pub, PreSharedKey: wgPSK1},
						{PublicKey: wgClient2Pub, PreSharedKey: wgPSK2},
					},
					Amnezia: buildTestAmnezia(false),
				},
			},
			{
				Type: "wireguard",
				Tag:  wgClientTag,
				Options: &option.WireGuardEndpointOptions{
					Name:       "awg0",
					MTU:        wgMTU,
					Address:    badoption.Listable[netip.Prefix]{netip.MustParsePrefix(wgClientAddr)},
					PrivateKey: wgClientPrivateKey,
					Peers: []option.WireGuardPeer{
						{PublicKey: wgServerPub, PreSharedKey: wgPSK1},
					},
					Amnezia: buildTestAmnezia(true),
				},
			},
			{
				Type: "wireguard",
				Tag:  wgPlainTag,
				Options: &option.WireGuardEndpointOptions{
					Name:       "wg0",
					MTU:        wgMTU,
					Address:    badoption.Listable[netip.Prefix]{netip.MustParsePrefix(wgServerSubnet)},
					PrivateKey: wgPlainPrivateKey,
					ListenPort: wgPlainListenPort,
					// Amnezia intentionally nil: plain wireguard must be skipped.
				},
			},
		},
	}
}

// buildTestAmnezia returns a shared AmneziaWG obfuscation block; when withClient
// is set, the client-only I1 field is populated.
func buildTestAmnezia(withClient bool) *option.WireGuardAmnezia {
	a := &option.WireGuardAmnezia{
		JC:   wgAmneziaJC,
		JMin: wgAmneziaJMin,
		JMax: wgAmneziaJMax,
		S1:   wgAmneziaS1,
		S2:   wgAmneziaS2,
		S3:   wgAmneziaS3,
		S4:   wgAmneziaS4,
		H1:   &badoption.Range[uint32]{From: wgH1From, To: wgH1To},
	}
	if withClient {
		a.I1 = wgClientI1
	}
	return a
}

func marshalRoundTrip(t *testing.T, opts *option.Options) *option.Options {
	t.Helper()
	ctx := include.Context(context.Background())
	data, err := singjson.MarshalContext(ctx, opts)
	if err != nil {
		t.Fatalf("marshal options: %v", err)
	}
	var parsed option.Options
	if err := singjson.UnmarshalContext(ctx, data, &parsed); err != nil {
		t.Fatalf("unmarshal options: %v", err)
	}
	return &parsed
}
