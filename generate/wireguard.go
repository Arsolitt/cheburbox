package generate

import (
	"fmt"
	"math"
	"net"
	"net/netip"
	"slices"
	"strconv"

	"github.com/Arsolitt/amnezigo"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"

	"github.com/Arsolitt/cheburbox/config"
)

// wgInterfaceName is the in-process WireGuard interface name used by every
// AmneziaWG endpoint. With System=false (the default) sing-box runs the
// userspace WireGuard stack, so no real tun device is created at construction.
const wgInterfaceName = "awg0"

const (
	defaultAmneziaProtocol = amnezigo.ProtocolQUIC
	defaultAmneziaMTU      = 1280
	// maxAmneziaMTU bounds the int->uint32 MTU conversion; real MTU values are
	// far smaller, so anything larger is treated as the default.
	maxAmneziaMTU = 65535
)

// maxPeerIPScan caps the linear scan for a free peer tunnel address so that a
// pathological /8 subnet cannot stall generation.
const maxPeerIPScan = 1 << 16

// headerProtectionNonceFloor is the smallest S-prefix accepted by AWG 3.x
// header protection: the ChaCha20 header-cipher nonce is the first S bytes of
// the packet, so the device refuses S < 12 whenever header protection is on
// (amnezigo generator.go headerProtectionNonceSize).
const headerProtectionNonceFloor = 12

// AWG 3.x transport-protection defaults mirrored from the amnezigo pipeline
// (pipeline.go resolveObfuscation): the values that flow emits when a manifest
// leaves the corresponding field unset.
//
//nolint:mnd // protocol defaults — the numeric literals are the domain values.
var (
	defaultAmneziaContentPadding       = amnezigo.U16Range{Min: 2, Max: 10}
	defaultAmneziaRekeyAfterTime       = amnezigo.U16Range{Min: 120, Max: 180}
	defaultAmneziaRekeyTimeout         = amnezigo.U16Range{Min: 5, Max: 8}
	defaultAmneziaRejectAfterTime      = amnezigo.U16Range{Min: 180, Max: 240}
	defaultAmneziaKeepaliveTimeout     = amnezigo.U16Range{Min: 8, Max: 12}
	defaultAmneziaMaxHandshakeAttempts = amnezigo.U16Range{Min: 16, Max: 20}
)

// toRangeUint32 maps an amnezigo HeaderRange to a sing-box badoption range.
func toRangeUint32(h amnezigo.HeaderRange) *badoption.Range[uint32] {
	return &badoption.Range[uint32]{From: h.Min, To: h.Max}
}

// toRangeFromU16 maps an amnezigo U16Range to a sing-box badoption range. The
// zero range means the parameter is unset/disabled, so it maps to nil and the
// JSON key is omitted (mirroring the amnezigo writer, which skips zero ranges).
func toRangeFromU16(r amnezigo.U16Range) *badoption.Range[uint32] {
	if r.IsZero() {
		return nil
	}
	return &badoption.Range[uint32]{From: uint32(r.Min), To: uint32(r.Max)}
}

// toAmneziaShared maps amnezigo server-side obfuscation params to a sing-box
// WireGuardAmnezia block. Shared params (Jc/Jmin/Jmax/S1-S4/H1-H4) must be
// identical on server and client; I1-I5 are client-only and omitted here. The
// AWG 3.x fields (header protection key and the six transport ranges) map when
// the target version sets them. RandomTrailers/DisableCookies are deliberately
// NOT mapped: option.WireGuardAmnezia has no such fields — sing-box-extended
// cannot express the 3.1 flags, so cheburbox pins them off on every side.
func toAmneziaShared(s amnezigo.ServerObfuscationConfig) option.WireGuardAmnezia {
	return option.WireGuardAmnezia{
		JC:   s.Jc,
		JMin: s.Jmin,
		JMax: s.Jmax,
		S1:   s.S1,
		S2:   s.S2,
		S3:   s.S3,
		S4:   s.S4,
		H1:   toRangeUint32(s.H1),
		H2:   toRangeUint32(s.H2),
		H3:   toRangeUint32(s.H3),
		H4:   toRangeUint32(s.H4),

		HeaderProtectionKey:    s.HeaderProtectionKey,
		ContentPaddingAddition: toRangeFromU16(s.ContentPadding),
		RekeyAfterTime:         toRangeFromU16(s.RekeyAfterTime),
		RekeyTimeout:           toRangeFromU16(s.RekeyTimeout),
		RejectAfterTime:        toRangeFromU16(s.RejectAfterTime),
		KeepaliveTimeout:       toRangeFromU16(s.KeepaliveTimeout),
		MaxHandshakeAttempts:   toRangeFromU16(s.MaxHandshakeAttempts),
	}
}

// cloneRangeUint32 returns a deep copy of a badoption uint32 range.
func cloneRangeUint32(r *badoption.Range[uint32]) *badoption.Range[uint32] {
	if r == nil {
		return nil
	}
	c := *r
	return &c
}

// cloneWGAmnezia returns a deep copy of a WireGuardAmnezia block. The pointer
// fields (H1-H4 and the six AWG 3.x ranges) are cloned individually so
// persisted/state copies do not alias the original.
func cloneWGAmnezia(a option.WireGuardAmnezia) option.WireGuardAmnezia {
	clone := a
	clone.H1 = cloneRangeUint32(a.H1)
	clone.H2 = cloneRangeUint32(a.H2)
	clone.H3 = cloneRangeUint32(a.H3)
	clone.H4 = cloneRangeUint32(a.H4)
	clone.ContentPaddingAddition = cloneRangeUint32(a.ContentPaddingAddition)
	clone.RekeyAfterTime = cloneRangeUint32(a.RekeyAfterTime)
	clone.RekeyTimeout = cloneRangeUint32(a.RekeyTimeout)
	clone.RejectAfterTime = cloneRangeUint32(a.RejectAfterTime)
	clone.KeepaliveTimeout = cloneRangeUint32(a.KeepaliveTimeout)
	clone.MaxHandshakeAttempts = cloneRangeUint32(a.MaxHandshakeAttempts)
	return clone
}

// generateAmneziaShared generates a fresh set of shared AmneziaWG obfuscation
// parameters for the requested AWG version from amnezigo building blocks.
//
// amnezigo.GenerateServerConfig and GenerateConfig take s1 and jc as LITERAL
// arguments: passing 0 yields literal S1=0 and Jc=0, not randomised values
// (verified in amnezigo/generator.go: GenerateConfig sets Jc: jc and derives S1
// from GenerateSPrefixesWithS1(s1)). To get fully random S1 and Jc — the correct
// behaviour for a real server — we compose the primitives directly:
// GenerateSPrefixes (random S1-S4), GenerateJunkParamsWithForbidden (random
// Jc/Jmin/Jmax avoiding the padded handshake sizes), and GenerateHeaderRanges
// (random H1-H4), exactly as GenerateServerConfig does internally minus the
// literal s1/jc override.
//
// For AWG 3.x the S-prefixes are drawn at or above the header-protection floor,
// H1-H4 collapse to the standard 1..4 ranges (the message type is encrypted, so
// type-id avoidance no longer applies — amnezigo pipeline.go fillMissingHeaders),
// and the block additionally carries a fresh header-protection key plus the
// mirrored transport-range defaults.
func generateAmneziaShared(version amnezigo.AWGVersion) (option.WireGuardAmnezia, error) {
	minS := 0
	if version >= amnezigo.AWG30 {
		minS = headerProtectionNonceFloor
	}
	s := amnezigo.GenerateSPrefixes(minS)
	forbidden := amnezigo.PaddedSizes(s.S1, s.S2, s.S3, s.S4)
	j, err := amnezigo.GenerateJunkParamsWithForbidden(forbidden)
	if err != nil {
		return option.WireGuardAmnezia{}, fmt.Errorf("generate amnezia junk params: %w", err)
	}
	h := amnezigo.GenerateHeaderRanges()
	cfg := amnezigo.ServerObfuscationConfig{
		Version: version,
		Jc:      j.Jc,
		Jmin:    j.Jmin,
		Jmax:    j.Jmax,
		S1:      s.S1,
		S2:      s.S2,
		S3:      s.S3,
		S4:      s.S4,
		H1:      h[0],
		H2:      h[1],
		H3:      h[2],
		H4:      h[3],
	}
	if version >= amnezigo.AWG30 {
		headers := standardAmneziaHeaderRanges()
		cfg.H1, cfg.H2, cfg.H3, cfg.H4 = headers[0], headers[1], headers[2], headers[3]
		cfg.HeaderProtectionKey = amnezigo.GenerateHeaderProtectionKey()
		cfg.ContentPadding = defaultAmneziaContentPadding
		cfg.RekeyAfterTime = defaultAmneziaRekeyAfterTime
		cfg.RekeyTimeout = defaultAmneziaRekeyTimeout
		cfg.RejectAfterTime = defaultAmneziaRejectAfterTime
		cfg.KeepaliveTimeout = defaultAmneziaKeepaliveTimeout
		cfg.MaxHandshakeAttempts = defaultAmneziaMaxHandshakeAttempts
	}
	return toAmneziaShared(cfg), nil
}

// standardAmneziaHeaderRanges returns the H1..H4 = 1..4 ranges recommended for
// AWG 3.x header protection: the message type is encrypted, so the WireGuard
// type-ids 1..4 are no longer observable (amnezigo pipeline.go
// standardHeaderRanges).
//
//nolint:mnd // protocol values — 1..4 are the WireGuard message type-ids.
func standardAmneziaHeaderRanges() [4]amnezigo.HeaderRange {
	return [4]amnezigo.HeaderRange{{Min: 1, Max: 1}, {Min: 2, Max: 2}, {Min: 3, Max: 3}, {Min: 4, Max: 4}}
}

// amneziaVersion resolves the effective AWG version for an amnezia config.
// Empty means "2.0" — deliberately NOT amnezigo's DefaultAWGVersion (3.1), so
// existing servers keep emitting the exact 2.0 key set until an operator opts
// in. Never pass "" to amnezigo.ParseAWGVersion directly: its empty value means
// 3.1.
func amneziaVersion(amnezia *config.AmneziaConfig) (amnezigo.AWGVersion, error) {
	raw := "2.0"
	if amnezia != nil && amnezia.Version != "" {
		raw = amnezia.Version
	}
	version, err := amnezigo.ParseAWGVersion(raw)
	if err != nil {
		return 0, fmt.Errorf("resolve amnezia version: %w", err)
	}
	return version, nil
}

// resolveServerAmnezia returns the shared amnezia block for a server endpoint.
// A persisted block wins verbatim only when its transport-protection state
// matches the requested version (persistedHasTP == wantTP): a 2.0 block under a
// 3.x request (or vice versa) is regenerated for the requested version — the
// endpoint private key persists separately and is unaffected. Otherwise, when
// a preset is named, the block is derived from that amnezigo preset (3.x adds
// the generated header-protection key, keeps the preset's ContentPadding
// verbatim and applies the mirrored range defaults); with no preset, a fresh
// fully-random block is generated for the requested version.
func resolveServerAmnezia(
	tag string,
	amnezia *config.AmneziaConfig,
	persisted config.PersistedCredentials,
) (option.WireGuardAmnezia, error) {
	version, err := amneziaVersion(amnezia)
	if err != nil {
		return option.WireGuardAmnezia{}, err
	}
	wantTP := version >= amnezigo.AWG30

	if ep, ok := persisted.WireGuardEndpoints[tag]; ok && ep.Amnezia != nil {
		persistedHasTP := ep.Amnezia.HeaderProtectionKey != ""
		if persistedHasTP == wantTP {
			return cloneWGAmnezia(*ep.Amnezia), nil
		}
	}

	preset := ""
	if amnezia != nil {
		preset = amnezia.Preset
	}
	if preset != "" {
		p, err := amnezigo.GetPreset(preset)
		if err != nil {
			return option.WireGuardAmnezia{}, fmt.Errorf("resolve amnezia preset %q: %w", preset, err)
		}
		s := p.ToServerObfuscation()
		s.Version = version
		if wantTP {
			s.HeaderProtectionKey = amnezigo.GenerateHeaderProtectionKey()
			s.RekeyAfterTime = defaultAmneziaRekeyAfterTime
			s.RekeyTimeout = defaultAmneziaRekeyTimeout
			s.RejectAfterTime = defaultAmneziaRejectAfterTime
			s.KeepaliveTimeout = defaultAmneziaKeepaliveTimeout
			s.MaxHandshakeAttempts = defaultAmneziaMaxHandshakeAttempts
		} else {
			// Presets target 3.1; a 2.0 request must emit exactly the 2.0 key
			// set, so the 3.x fields the preset carries are cleared.
			s.ContentPadding = amnezigo.U16Range{}
			s.HeaderProtectionKey = ""
		}
		s.RandomTrailers = false
		s.DisableCookies = false
		return toAmneziaShared(s), nil
	}
	return generateAmneziaShared(version)
}

// resolveWGPrivateKey returns the server endpoint's private/public key pair.
// The private key is reused from persisted credentials if present; otherwise a
// fresh X25519 pair is generated. amnezigo.GenerateKeyPair panics only on
// crypto/rand failure, which does not occur in practice on Linux.
func resolveWGPrivateKey(tag string, persisted config.PersistedCredentials) (string, string) {
	if ep, ok := persisted.WireGuardEndpoints[tag]; ok && ep.PrivateKey != "" {
		return ep.PrivateKey, amnezigo.DerivePublicKey(ep.PrivateKey)
	}
	priv, pub := amnezigo.GenerateKeyPair()
	return priv, pub
}

// resolveClientWGKey returns the client's own private/public key pair. The
// private key is reused from persisted credentials when present; otherwise a
// fresh pair is generated. The returned public key is always derived from the
// returned private key, so the two can never drift.
func resolveClientWGKey(tag string, persisted config.PersistedCredentials) (string, string) {
	if ep, ok := persisted.WireGuardEndpoints[tag]; ok && ep.PrivateKey != "" {
		return ep.PrivateKey, amnezigo.DerivePublicKey(ep.PrivateKey)
	}
	priv, pub := amnezigo.GenerateKeyPair()
	return priv, pub
}

// generateWGPeerCreds generates a fresh AmneziaWG peer: an X25519 keypair plus a
// preshared key.
func generateWGPeerCreds(allowedIPs []netip.Prefix) AmneziaWGPeerCreds {
	priv, pub := amnezigo.GenerateKeyPair()
	return AmneziaWGPeerCreds{
		PrivateKey:   priv,
		PublicKey:    pub,
		PresharedKey: amnezigo.GeneratePSK(),
		AllowedIPs:   allowedIPs,
	}
}

// reuseClientPresharedKey returns the preshared key persisted on the client
// endpoint's single peer (the server), if any. A client endpoint has exactly
// one peer, so the first non-empty preshared key wins.
func reuseClientPresharedKey(tag string, persisted config.PersistedCredentials) string {
	ep, ok := persisted.WireGuardEndpoints[tag]
	if !ok {
		return ""
	}
	for _, peer := range ep.Peers {
		if peer.PresharedKey != "" {
			return peer.PresharedKey
		}
	}
	return ""
}

// amneziaProtocolMTU resolves the AmneziaWG transport protocol and MTU from an
// optional AmneziaConfig, falling back to a separate MTU source and finally to
// the defaults (quic / 1280). The returned MTU is a uint32 ready for sing-box.
func amneziaProtocolMTU(amnezia *config.AmneziaConfig, fallbackMTU int) (string, uint32) {
	protocol := defaultAmneziaProtocol
	if amnezia != nil && amnezia.Protocol != "" {
		protocol = amnezia.Protocol
	}

	mtu := defaultAmneziaMTU
	switch {
	case amnezia != nil && amnezia.MTU > 0:
		mtu = amnezia.MTU
	case fallbackMTU > 0:
		mtu = fallbackMTU
	}
	if mtu <= 0 || mtu > maxAmneziaMTU {
		mtu = defaultAmneziaMTU
	}

	return protocol, uint32(mtu)
}

// parseAddressPrefixes parses a list of CIDR strings into the sing-box Listable
// prefix form expected on an endpoint's Address field. Unparseable entries are
// skipped; callers validate addresses beforehand.
func parseAddressPrefixes(addrs []string) badoption.Listable[netip.Prefix] {
	out := make([]netip.Prefix, 0, len(addrs))
	for _, a := range addrs {
		if p, err := netip.ParsePrefix(a); err == nil {
			out = append(out, p)
		}
	}
	return out
}

// toListablePrefixes converts a slice of prefixes to the sing-box Listable type.
func toListablePrefixes(prefixes []netip.Prefix) badoption.Listable[netip.Prefix] {
	return badoption.Listable[netip.Prefix](prefixes)
}

// allAllowedIPs returns the default AllowedIPs a client routes through its
// server peer: all IPv4 and all IPv6.
func allAllowedIPs() badoption.Listable[netip.Prefix] {
	return badoption.Listable[netip.Prefix]{
		netip.MustParsePrefix("0.0.0.0/0"),
		netip.MustParsePrefix("::/0"),
	}
}

// allocatePeerAllowedIPs picks the next free /32 (or /128 for IPv6) host address
// inside serverSubnet, skipping the server's own address and any address already
// claimed by an existing peer. Used for AmneziaWG inbound users that have no
// cross-server outbound to supply an address.
func allocatePeerAllowedIPs(
	serverSubnet netip.Prefix,
	existing map[string]AmneziaWGPeerCreds,
) []netip.Prefix {
	hostBits := 32
	if serverSubnet.Addr().Is6() {
		hostBits = 128
	}

	used := make(map[netip.Addr]bool, len(existing)+1)
	used[serverSubnet.Addr()] = true // reserve the server tunnel address

	for _, p := range existing {
		for _, pfx := range p.AllowedIPs {
			used[pfx.Addr()] = true
		}
	}

	addr := serverSubnet.Addr().Next()
	for range maxPeerIPScan {
		if !addr.IsValid() || !serverSubnet.Contains(addr) {
			break
		}
		if !used[addr] {
			return []netip.Prefix{netip.PrefixFrom(addr, hostBits)}
		}
		addr = addr.Next()
	}

	// Subnet exhausted or too small to scan; fall back to the subnet itself.
	return []netip.Prefix{serverSubnet}
}

// buildServerWGPeers assembles the sing-box peer list for a server endpoint from
// the provisioned peer registry. Each peer's AllowedIPs is the peer's tunnel
// address; the peer's PublicKey and PreSharedKey come from the registry. Peers
// are emitted in sorted map-key (user name) order so the output is stable
// across runs (Go map iteration order is randomized).
func buildServerWGPeers(peers map[string]AmneziaWGPeerCreds) []option.WireGuardPeer {
	keys := make([]string, 0, len(peers))
	for k := range peers {
		keys = append(keys, k)
	}
	slices.Sort(keys)

	result := make([]option.WireGuardPeer, 0, len(peers))
	for _, k := range keys {
		p := peers[k]
		result = append(result, option.WireGuardPeer{
			PublicKey:    p.PublicKey,
			PreSharedKey: p.PresharedKey,
			AllowedIPs:   toListablePrefixes(p.AllowedIPs),
		})
	}
	return result
}

// buildClientAmnezia composes the client amnezia block: the shared params
// (Jc/Jmin/Jmax/S1-S4/H1-H4 and the AWG 3.x transport-protection fields) are
// copied verbatim from the server so both ends match, and client-only I1-I5 are
// freshly generated via amnezigo.GenerateCPS seeded with the server's S1.
func buildClientAmnezia(shared option.WireGuardAmnezia, protocol string, mtu int) option.WireGuardAmnezia {
	i1, i2, i3, i4, i5 := amnezigo.GenerateCPS(protocol, mtu, shared.S1, 0)
	return option.WireGuardAmnezia{
		JC:   shared.JC,
		JMin: shared.JMin,
		JMax: shared.JMax,
		S1:   shared.S1,
		S2:   shared.S2,
		S3:   shared.S3,
		S4:   shared.S4,
		H1:   cloneRangeUint32(shared.H1),
		H2:   cloneRangeUint32(shared.H2),
		H3:   cloneRangeUint32(shared.H3),
		H4:   cloneRangeUint32(shared.H4),

		HeaderProtectionKey:    shared.HeaderProtectionKey,
		ContentPaddingAddition: cloneRangeUint32(shared.ContentPaddingAddition),
		RekeyAfterTime:         cloneRangeUint32(shared.RekeyAfterTime),
		RekeyTimeout:           cloneRangeUint32(shared.RekeyTimeout),
		RejectAfterTime:        cloneRangeUint32(shared.RejectAfterTime),
		KeepaliveTimeout:       cloneRangeUint32(shared.KeepaliveTimeout),
		MaxHandshakeAttempts:   cloneRangeUint32(shared.MaxHandshakeAttempts),

		I1: i1,
		I2: i2,
		I3: i3,
		I4: i4,
		I5: i5,
	}
}

// resolvePeerEndpoint returns the (host, port) a client should dial for its
// server peer. The server's registered endpoint is used by default; an explicit
// outbound Endpoint override (host or host:port) takes precedence.
func resolvePeerEndpoint(target AmneziaWGServerInfo, override string) (string, uint16) {
	if override == "" {
		if host, _, err := net.SplitHostPort(target.EndpointAddr); err == nil {
			return host, target.ListenPort
		}
		return target.EndpointAddr, target.ListenPort
	}

	if host, portStr, err := net.SplitHostPort(override); err == nil {
		if p, perr := strconv.Atoi(portStr); perr == nil && p > 0 && p <= math.MaxUint16 {
			return host, uint16(p)
		}
		return host, target.ListenPort
	}

	// Override carries no port: treat it as a host and keep the server's port.
	return override, target.ListenPort
}

// BuildAmneziaWGServerEndpoint builds a sing-box wireguard endpoint for an
// AmneziaWG inbound (server side). The server's private key and shared amnezia
// parameters are reused from persisted credentials when available so they stay
// stable across generation runs. Declared inbound users are provisioned as peers
// (each allocated a /32 from the inbound subnet); cross-server clients provision
// themselves into the same registry when their own client endpoint is built.
// The server info is registered in state so client endpoints can look it up.
func BuildAmneziaWGServerEndpoint(
	in config.Inbound,
	serverName, endpointAddr string,
	state *ServerState,
	persisted config.PersistedCredentials,
) (*option.Endpoint, error) {
	if len(in.Address) == 0 {
		return nil, fmt.Errorf("amneziawg inbound %q requires exactly one CIDR address", in.Tag)
	}
	subnet, err := netip.ParsePrefix(in.Address[0])
	if err != nil {
		return nil, fmt.Errorf("amneziawg inbound %q address %q: %w", in.Tag, in.Address[0], err)
	}
	if in.ListenPort < 0 || in.ListenPort > math.MaxUint16 {
		return nil, fmt.Errorf("amneziawg inbound %q listen_port %d out of range", in.Tag, in.ListenPort)
	}

	protocol, mtu := amneziaProtocolMTU(in.Amnezia, in.MTU)

	// Resolve the server private key and shared amnezia block. A regeneration
	// pass (triggered by a cross-server client provisioning a new peer) MUST
	// reuse the first pass's material, otherwise the client's already-built peer
	// — which captured the first pass's public key — would desynchronise. The
	// state cache holds it for the lifetime of one GenerateAll run; persisted
	// config.json keeps it stable across runs.
	var serverPriv, serverPub string
	var shared option.WireGuardAmnezia
	if mat, ok := state.lookupAmneziaWGMaterial(serverName, in.Tag); ok {
		serverPriv = mat.PrivateKey
		serverPub = amnezigo.DerivePublicKey(serverPriv)
		shared = cloneWGAmnezia(mat.Amnezia)
	} else {
		serverPriv, serverPub = resolveWGPrivateKey(in.Tag, persisted)

		shared, err = resolveServerAmnezia(in.Tag, in.Amnezia, persisted)
		if err != nil {
			return nil, fmt.Errorf("resolve amnezia params: %w", err)
		}

		state.storeAmneziaWGMaterial(serverName, in.Tag, amneziaWGServerMaterial{
			PrivateKey: serverPriv,
			Amnezia:    shared,
		})
	}

	// Provision declared inbound users as peers. Users reached via a
	// cross-server outbound are provisioned by the client endpoint builder
	// instead; declared users still need a server-side peer entry with an
	// allocated tunnel IP.
	existing := state.AmneziaWGPeers(serverName, in.Tag)
	for _, user := range in.Users {
		if _, ok := state.AmneziaWGPeer(serverName, in.Tag, user.Name); ok {
			continue
		}
		allowed := allocatePeerAllowedIPs(subnet, existing)
		creds := generateWGPeerCreds(allowed)
		creds, _ = state.EnsureAmneziaWGPeer(serverName, in.Tag, user.Name, creds)
		if existing == nil {
			existing = make(map[string]AmneziaWGPeerCreds)
		}
		existing[user.Name] = creds
	}

	listenPort := uint16(in.ListenPort)
	state.RegisterAmneziaWGServer(serverName, in.Tag, AmneziaWGServerInfo{
		PublicKey:     serverPub,
		EndpointAddr:  net.JoinHostPort(endpointAddr, strconv.Itoa(in.ListenPort)),
		ListenPort:    listenPort,
		Protocol:      protocol,
		SharedAmnezia: shared,
		Subnet:        subnet,
		MTU:           mtu,
	})

	endpointAmnezia := cloneWGAmnezia(shared)

	return &option.Endpoint{
		Type: EndpointTypeWireGuard,
		Tag:  in.Tag,
		Options: &option.WireGuardEndpointOptions{
			Name:       wgInterfaceName,
			MTU:        mtu,
			Address:    parseAddressPrefixes(in.Address),
			PrivateKey: serverPriv,
			ListenPort: listenPort,
			Peers:      buildServerWGPeers(state.AmneziaWGPeers(serverName, in.Tag)),
			Amnezia:    &endpointAmnezia,
		},
	}, nil
}

// BuildAmneziaWGClientEndpoint builds a sing-box wireguard endpoint for an
// AmneziaWG outbound (client side). The target server must already be registered
// in state (topological order guarantees this). The client's private key is
// reused from persisted credentials when available; its derived public key is
// provisioned into the target server's peer registry so the server's peer list
// stays consistent with the client's key across runs. The shared amnezia params
// are inherited from the server; client-only I1-I5 are freshly generated.
func BuildAmneziaWGClientEndpoint(
	out config.Outbound,
	serverName string,
	state *ServerState,
	persisted config.PersistedCredentials,
) (*option.Endpoint, error) {
	target, ok := state.AmneziaWGServer(out.Server, out.Inbound)
	if !ok {
		return nil, fmt.Errorf(
			"amneziawg outbound %q targets server %q inbound %q which has no built server endpoint",
			out.Tag, out.Server, out.Inbound,
		)
	}

	if len(out.Address) == 0 {
		return nil, fmt.Errorf("amneziawg outbound %q requires exactly one CIDR address", out.Tag)
	}
	clientAllowed, err := netip.ParsePrefix(out.Address[0])
	if err != nil {
		return nil, fmt.Errorf("amneziawg outbound %q address %q: %w", out.Tag, out.Address[0], err)
	}

	user := out.User
	if user == "" {
		user = serverName
	}

	// The public key registered on the server is derived from the client's own
	// (persisted or fresh) private key, so the two can never drift across runs.
	clientPriv, clientPub := resolveClientWGKey(out.Tag, persisted)

	// Reuse the preshared key from the client's persisted single peer (the
	// server) when available; otherwise generate a fresh one.
	psk := reuseClientPresharedKey(out.Tag, persisted)
	if psk == "" {
		psk = amnezigo.GeneratePSK()
	}

	// Provision this client as a peer on the target server (idempotent by user).
	state.EnsureAmneziaWGPeer(out.Server, out.Inbound, user, AmneziaWGPeerCreds{
		PublicKey:    clientPub,
		PresharedKey: psk,
		AllowedIPs:   []netip.Prefix{clientAllowed},
	})

	// Client MTU: prefer the outbound's, else inherit the server's.
	_, mtu := amneziaProtocolMTU(nil, out.MTU)
	if out.MTU == 0 {
		mtu = target.MTU
	}

	clientAmnezia := buildClientAmnezia(target.SharedAmnezia, target.Protocol, int(mtu))

	peerHost, peerPort := resolvePeerEndpoint(target, out.Endpoint)

	return &option.Endpoint{
		Type: EndpointTypeWireGuard,
		Tag:  out.Tag,
		Options: &option.WireGuardEndpointOptions{
			Name:       wgInterfaceName,
			MTU:        mtu,
			Address:    parseAddressPrefixes(out.Address),
			PrivateKey: clientPriv,
			Peers: []option.WireGuardPeer{{
				Address:      peerHost,
				Port:         peerPort,
				PublicKey:    target.PublicKey,
				PreSharedKey: psk,
				AllowedIPs:   allAllowedIPs(),
			}},
			Amnezia: &clientAmnezia,
		},
	}, nil
}

// partitionAmneziaWG splits a config's inbounds and outbounds into AmneziaWG
// entries (handled as sing-box endpoints) and the rest (handled as regular
// sing-box inbounds/outbounds). This keeps the inbound/outbound builders from
// encountering the unsupported amneziawg type.
func partitionAmneziaWG(cfg config.Config) ([]config.Inbound, []config.Outbound) {
	singInbounds := make([]config.Inbound, 0, len(cfg.Inbounds))
	for _, in := range cfg.Inbounds {
		if in.Type != TypeAmneziaWG {
			singInbounds = append(singInbounds, in)
		}
	}

	singOutbounds := make([]config.Outbound, 0, len(cfg.Outbounds))
	for _, out := range cfg.Outbounds {
		if out.Type != TypeAmneziaWG {
			singOutbounds = append(singOutbounds, out)
		}
	}

	return singInbounds, singOutbounds
}

// buildAmneziaWGEndpoints builds the sing-box wireguard endpoints for all
// AmneziaWG inbounds (server side) and outbounds (client side) in cfg. Server
// endpoints are built first so their state is available to client endpoints on
// the same server. Cross-server client endpoints look up their target server's
// state (registered when the target was processed earlier in topological order)
// and provision themselves into the target's peer registry; the caller marks the
// target dirty so it is regenerated with the new peer.
func buildAmneziaWGEndpoints(
	cfg config.Config,
	serverName string,
	state *ServerState,
	persisted config.PersistedCredentials,
) ([]option.Endpoint, error) {
	var endpoints []option.Endpoint

	for _, in := range cfg.Inbounds {
		if in.Type != TypeAmneziaWG {
			continue
		}
		ep, err := BuildAmneziaWGServerEndpoint(in, serverName, cfg.Endpoint, state, persisted)
		if err != nil {
			return nil, err
		}
		endpoints = append(endpoints, *ep)
	}

	for _, out := range cfg.Outbounds {
		if out.Type != TypeAmneziaWG {
			continue
		}
		ep, err := BuildAmneziaWGClientEndpoint(out, serverName, state, persisted)
		if err != nil {
			return nil, err
		}
		endpoints = append(endpoints, *ep)
	}

	return endpoints, nil
}
