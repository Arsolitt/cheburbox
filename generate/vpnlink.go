package generate

import (
	"bytes"
	"fmt"
	"net"
	"net/netip"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/Arsolitt/amnezigo"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"

	"github.com/Arsolitt/cheburbox/config"
)

// maxVPNDNSServers caps the plain-IP DNS servers written into a vpn:// link's
// INI. AmneziaVPN applies only the first two; more would be ignored.
const maxVPNDNSServers = 2

// buildVPNLinkFiles returns AmneziaVPN vpn:// link FileOutputs for server when
// it is a selected peer, or (nil, nil) when vpn links are disabled. The error
// is wrapped for the generateServerWithState call site.
func buildVPNLinkFiles(
	genCfg GenerateConfig,
	serverName string,
	cfg config.Config,
	endpoints []option.Endpoint,
) ([]FileOutput, error) {
	if !genCfg.WantsVPNLinks(serverName) {
		return nil, nil
	}
	files, err := awgVPNLinkFiles(cfg, endpoints)
	if err != nil {
		return nil, fmt.Errorf("build amneziawg vpn links: %w", err)
	}
	return files, nil
}

// awgVPNLinkFiles builds AmneziaVPN vpn:// import-link FileOutputs for every
// amneziawg outbound on this server. Each outbound's built client endpoint
// (matched by tag) becomes links/<tag>.vpn. Endpoints whose options are not a
// wireguard client endpoint, or that lack an Amnezia block or peers, are
// skipped — by construction a real AWG client endpoint has exactly one peer and
// a non-nil Amnezia block.
func awgVPNLinkFiles(cfg config.Config, endpoints []option.Endpoint) ([]FileOutput, error) {
	dns := plainIPDNSServers(cfg.DNS.Servers)

	var files []FileOutput
	for _, out := range cfg.Outbounds {
		if out.Type != TypeAmneziaWG {
			continue
		}
		ep := endpointByTag(endpoints, out.Tag)
		if ep == nil {
			continue
		}
		wg, ok := ep.Options.(*option.WireGuardEndpointOptions)
		if !ok || wg.Amnezia == nil || len(wg.Peers) == 0 {
			continue
		}

		ini, err := awgClientINI(wg, dns)
		if err != nil {
			return nil, fmt.Errorf("endpoint %q: %w", out.Tag, err)
		}

		peer := wg.Peers[0]
		peerEndpoint := net.JoinHostPort(peer.Address, strconv.Itoa(int(peer.Port)))
		description := vpnDisplayName(out.Tag)
		link := amnezigo.EncodeVPNLink(ini, peerEndpoint, int(peer.Port), dns, description)

		files = append(files, FileOutput{
			Path:    filepath.Join("links", out.Tag+".vpn"),
			Content: []byte(link),
		})
	}

	return files, nil
}

// endpointByTag returns a pointer to the endpoint with the matching tag, or nil
// if none exists.
func endpointByTag(endpoints []option.Endpoint, tag string) *option.Endpoint {
	for i := range endpoints {
		if endpoints[i].Tag == tag {
			return &endpoints[i]
		}
	}
	return nil
}

// vpnDisplayName derives the AmneziaVPN app display name for an amneziawg
// outbound's vpn:// link from the outbound tag. The conventional tag shape is
// <server>-awg-<preset>-<protocol> (e.g. al-p-1-awg-stealth-dns); the "awg"
// token is collapsed so the app shows al-p-1-stealth-dns. Tags without the
// "-awg-" segment are returned unchanged. An empty tag yields an empty name,
// which leaves envelope.description unset (omitempty) and lets AmneziaVPN fall
// back to hostName.
func vpnDisplayName(tag string) string {
	return strings.Replace(tag, "-awg-", "-", 1)
}

// awgClientINI renders a sing-box wireguard client endpoint as an AWG client
// INI via amnezigo.WriteClientConfig. The DNS list is joined into the Interface
// DNS line; WriteClientConfig always emits a "DNS =" line even when empty.
func awgClientINI(wg *option.WireGuardEndpointOptions, dns []string) ([]byte, error) {
	peer := wg.Peers[0]
	a := wg.Amnezia

	clientCfg := amnezigo.ClientConfig{
		Interface: amnezigo.ClientInterfaceConfig{
			PrivateKey: wg.PrivateKey,
			Address:    joinPrefixes(wg.Address),
			DNS:        strings.Join(dns, ", "),
			MTU:        int(wg.MTU),
			Obfuscation: amnezigo.ClientObfuscationConfig{
				I1: a.I1,
				I2: a.I2,
				I3: a.I3,
				I4: a.I4,
				I5: a.I5,
				ServerObfuscationConfig: amnezigo.ServerObfuscationConfig{
					Jc:   a.JC,
					Jmin: a.JMin,
					Jmax: a.JMax,
					S1:   a.S1,
					S2:   a.S2,
					S3:   a.S3,
					S4:   a.S4,
					H1:   fromBadRange(a.H1),
					H2:   fromBadRange(a.H2),
					H3:   fromBadRange(a.H3),
					H4:   fromBadRange(a.H4),
				},
			},
		},
		Peer: amnezigo.ClientPeerConfig{
			PublicKey:           peer.PublicKey,
			PresharedKey:        peer.PreSharedKey,
			Endpoint:            net.JoinHostPort(peer.Address, strconv.Itoa(int(peer.Port))),
			AllowedIPs:          joinPrefixes(peer.AllowedIPs),
			PersistentKeepalive: int(peer.PersistentKeepaliveInterval),
		},
	}

	var buf bytes.Buffer
	if err := amnezigo.WriteClientConfig(&buf, clientCfg); err != nil {
		return nil, fmt.Errorf("write client ini: %w", err)
	}
	return buf.Bytes(), nil
}

// joinPrefixes renders a sing-box Listable prefix slice as a comma-space joined
// CIDR string (e.g. "0.0.0.0/0, ::/0").
func joinPrefixes(p badoption.Listable[netip.Prefix]) string {
	parts := make([]string, len(p))
	for i, prefix := range p {
		parts[i] = prefix.String()
	}
	return strings.Join(parts, ", ")
}

// fromBadRange converts a sing-box badoption uint32 range to an amnezigo
// HeaderRange. A nil pointer yields a zero-value HeaderRange (defensive: AWG
// client endpoints always populate H1-H4 non-nil).
func fromBadRange(r *badoption.Range[uint32]) amnezigo.HeaderRange {
	if r == nil {
		return amnezigo.HeaderRange{}
	}
	return amnezigo.HeaderRange{Min: r.From, Max: r.To}
}

// plainIPDNSServers keeps DNS server entries whose Server field is a plain IP
// address (parsable via netip.ParseAddr), preserving config order and capped at
// maxVPNDNSServers. DoH/TLS/localhost/empty entries are skipped because a
// standalone AmneziaVPN tunnel cannot dial a detour-based resolver.
func plainIPDNSServers(servers []config.DNSServer) []string {
	var result []string
	for _, s := range servers {
		if s.Server == "" {
			continue
		}
		if _, err := netip.ParseAddr(s.Server); err != nil {
			continue
		}
		result = append(result, s.Server)
		if len(result) >= maxVPNDNSServers {
			break
		}
	}
	return result
}
