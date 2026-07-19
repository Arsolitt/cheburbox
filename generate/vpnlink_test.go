package generate

import (
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"encoding/json"
	"net/netip"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"

	"github.com/Arsolitt/cheburbox/config"
)

// filePaths collects the Path of each FileOutput for readable failure output.
func filePaths(files []FileOutput) []string {
	paths := make([]string, len(files))
	for i, f := range files {
		paths[i] = f.Path
	}
	return paths
}

// qCompressHeaderSize mirrors amnezigo's qCompress header: a big-endian uint32
// holding the uncompressed length, written before the zlib-compressed payload.
const qCompressHeaderSize = 4

// decodeVPNDescription extracts the envelope "description" field from a vpn://
// link by reversing amnezigo's encode path (vpn:// + base64url of
// qCompress(zlib(envelopeJSON))). It exists only for tests that assert the
// description is threaded into the generated link.
func decodeVPNDescription(t *testing.T, link string) string {
	t.Helper()
	compressed, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(link, "vpn://"))
	if err != nil {
		t.Fatalf("base64url decode: %v", err)
	}
	zr, err := zlib.NewReader(bytes.NewReader(compressed[qCompressHeaderSize:]))
	if err != nil {
		t.Fatalf("zlib reader: %v", err)
	}
	defer zr.Close()
	var env struct {
		Description string `json:"description"`
	}
	if err := json.NewDecoder(zr).Decode(&env); err != nil {
		t.Fatalf("decode envelope: %v", err)
	}
	return env.Description
}

// setupAWGCrossServerFixture provisions a two-server project: awg-server hosts
// an amneziawg inbound, awg-client has an amneziawg outbound targeting it. This
// mirrors the real cross-server AWG flow that produces client endpoints.
func setupAWGCrossServerFixture(t *testing.T, projectRoot string) {
	t.Helper()

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
}

// TestAWGVPNLinkFiles_GeneratesLinkForClient verifies that selecting a peer via
// VPNLinkPeers emits a links/<tag>.vpn file holding a vpn:// link for its single
// amneziawg outbound, and that the server (which has no amneziawg outbound) gets
// no link file.
func TestAWGVPNLinkFiles_GeneratesLinkForClient(t *testing.T) {
	t.Parallel()

	projectRoot := t.TempDir()
	setupAWGCrossServerFixture(t, projectRoot)

	results, err := GenerateAll(projectRoot, "lib", GenerateConfig{
		VPNLinkPeers: []string{"awg-client"},
	})
	if err != nil {
		t.Fatalf("GenerateAll: %v", err)
	}

	client := findResultByName(results, "awg-client")
	if client == nil {
		t.Fatal("awg-client result not found")
	}

	link := findFile(client.Files, "links/awg-out.vpn")
	if link == nil {
		t.Fatalf("awg-client has no links/awg-out.vpn; files: %v", filePaths(client.Files))
	}
	if !strings.HasPrefix(string(link.Content), "vpn://") {
		t.Errorf("link content does not start with vpn://: %q", string(link.Content))
	}
	if got := decodeVPNDescription(t, string(link.Content)); got != "awg-out" {
		t.Errorf("link description = %q, want %q", got, "awg-out")
	}

	// The server has an amneziawg inbound, not an outbound, so it must not
	// receive a vpn link file.
	server := findResultByName(results, "awg-server")
	if server == nil {
		t.Fatal("awg-server result not found")
	}
	for _, f := range server.Files {
		if strings.Contains(f.Path, "links/") {
			t.Errorf("awg-server must not get a vpn link file, found %s", f.Path)
		}
	}
}

// TestAWGVPNLinkFiles_DisabledByDefault verifies that with an empty
// GenerateConfig (the default) no links/ files are produced on any server.
func TestAWGVPNLinkFiles_DisabledByDefault(t *testing.T) {
	t.Parallel()

	projectRoot := t.TempDir()
	setupAWGCrossServerFixture(t, projectRoot)

	results, err := GenerateAll(projectRoot, "lib", GenerateConfig{})
	if err != nil {
		t.Fatalf("GenerateAll: %v", err)
	}

	for _, r := range results {
		for _, f := range r.Files {
			if strings.Contains(f.Path, "links/") {
				t.Errorf("server %s has unexpected link file %s (vpn links disabled by default)",
					r.Server, f.Path)
			}
		}
	}
}

// TestAWGClientINI_PreservesFields guards the sing-box-to-INI field mapping by
// asserting every relevant AWG field survives the conversion with the expected
// value.
func TestAWGClientINI_PreservesFields(t *testing.T) {
	t.Parallel()

	const privKey = "cHJpdmF0ZWtleWJhc2U2NA=="

	wg := &option.WireGuardEndpointOptions{
		MTU:        1280,
		Address:    badoption.Listable[netip.Prefix]{netip.MustParsePrefix("10.7.0.2/32")},
		PrivateKey: privKey,
		Peers: []option.WireGuardPeer{
			{
				Address:      "203.0.113.10",
				Port:         51820,
				PublicKey:    "serverPubKey",
				PreSharedKey: "pskValue",
				AllowedIPs: badoption.Listable[netip.Prefix]{
					netip.MustParsePrefix("0.0.0.0/0"),
					netip.MustParsePrefix("::/0"),
				},
				PersistentKeepaliveInterval: 25,
			},
		},
		Amnezia: &option.WireGuardAmnezia{
			JC:   5,
			JMin: 10,
			JMax: 20,
			S1:   30,
			S2:   40,
			S3:   50,
			S4:   60,
			H1:   &badoption.Range[uint32]{From: 1, To: 100},
			I1:   "deadbeef",
		},
	}

	ini, err := awgClientINI(wg, []string{"1.1.1.1", "8.8.8.8"})
	if err != nil {
		t.Fatalf("awgClientINI: %v", err)
	}
	text := string(ini)

	wantSubstrings := []string{
		"PrivateKey = " + privKey,
		"Address = 10.7.0.2/32",
		"DNS = 1.1.1.1, 8.8.8.8",
		"MTU = 1280",
		"Jc = 5",
		"Jmin = 10",
		"Jmax = 20",
		"S1 = 30",
		"S4 = 60",
		"H1 = 1-100",
		"I1 = deadbeef",
		"PublicKey = serverPubKey",
		"PresharedKey = pskValue",
		"Endpoint = 203.0.113.10:51820",
		"AllowedIPs = 0.0.0.0/0, ::/0",
		"PersistentKeepalive = 25",
	}
	for _, want := range wantSubstrings {
		if !strings.Contains(text, want) {
			t.Errorf("INI missing %q\n--- INI ---\n%s", want, text)
		}
	}
}

// TestVPNDisplayName covers the tag → app display name derivation. The
// conventional tag shape is <server>-awg-<preset>-<protocol>; the "-awg-"
// token collapses to a single dash. Tags missing the segment are unchanged.
// The empty case is documented: vpnDisplayName("") returns "", which leaves
// envelope.description unset (amnezigo tags it omitempty) and lets AmneziaVPN
// fall back to hostName.
func TestVPNDisplayName(t *testing.T) {
	t.Parallel()
	cases := []struct{ in, want string }{
		{"al-p-1-awg-stealth-dns", "al-p-1-stealth-dns"},
		{"am-p-1-awg-stealth-quic", "am-p-1-stealth-quic"},
		{"", ""},
		{"awg-out", "awg-out"},
		{"awg-foo", "awg-foo"},
		{"x-awg", "x-awg"},
	}
	for _, c := range cases {
		if got := vpnDisplayName(c.in); got != c.want {
			t.Errorf("vpnDisplayName(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
