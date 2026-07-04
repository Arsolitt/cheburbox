package config

import (
	"context"
	"fmt"
	"os"

	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	singjson "github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/json/badoption"
)

// PersistedCredentials holds all credentials extracted from a sing-box config.json.
type PersistedCredentials struct {
	InboundUsers       map[string]map[string]UserCredentials
	RealityKeys        map[string]RealityKeyPair
	ObfsPasswords      map[string]string
	WireGuardEndpoints map[string]WireGuardEndpointCreds
}

// UserCredentials holds UUID or password for a single inbound user.
type UserCredentials struct {
	UUID     string
	Password string
	Flow     string
}

// RealityKeyPair holds Reality TLS key material for an inbound.
type RealityKeyPair struct {
	PrivateKey string
	PublicKey  string
	ShortID    []string
}

// WireGuardEndpointCreds holds persisted credentials for one wireguard endpoint.
// Only endpoints with a non-nil Amnezia block (i.e. AmneziaWG) are persisted;
// plain wireguard endpoints are skipped.
type WireGuardEndpointCreds struct {
	Amnezia    *option.WireGuardAmnezia
	Peers      map[string]WireGuardPeerCreds
	PrivateKey string
}

// WireGuardPeerCreds holds persisted per-peer key material. The endpoint's own
// private key lives at WireGuardEndpointCreds.PrivateKey (set for both server
// and client endpoints); per-peer we keep the peer PublicKey and PresharedKey.
// The map is keyed by peer PublicKey since wireguard peers carry no name field.
type WireGuardPeerCreds struct {
	PublicKey    string
	PresharedKey string
}

// EmptyPersistedCredentials returns a zero-value PersistedCredentials with
// initialized maps.
func EmptyPersistedCredentials() PersistedCredentials {
	return PersistedCredentials{
		InboundUsers:       make(map[string]map[string]UserCredentials),
		RealityKeys:        make(map[string]RealityKeyPair),
		ObfsPasswords:      make(map[string]string),
		WireGuardEndpoints: make(map[string]WireGuardEndpointCreds),
	}
}

// LoadPersistedCredentials reads a sing-box config.json from configPath,
// parses it using sing-box option structs, and extracts all credentials.
// A generated config.json carries its wireguard endpoints under the top-level
// "endpoints" array; option.Options deserializes them into Endpoints, where
// ExtractCredentials picks up the AmneziaWG ones. Returns empty credentials if
// the file does not exist.
func LoadPersistedCredentials(configPath string) (PersistedCredentials, error) {
	data, err := os.ReadFile(configPath)
	if os.IsNotExist(err) {
		return EmptyPersistedCredentials(), nil
	}
	if err != nil {
		return PersistedCredentials{}, fmt.Errorf("read %s: %w", configPath, err)
	}

	ctx := include.Context(context.Background())
	var opts option.Options
	if err := singjson.UnmarshalContext(ctx, data, &opts); err != nil {
		return PersistedCredentials{}, fmt.Errorf("parse %s: %w", configPath, err)
	}

	return ExtractCredentials(&opts), nil
}

// ExtractCredentials extracts all credentials from a parsed sing-box Options
// struct, including VLESS users with UUIDs, Hysteria2 users with passwords,
// Reality key pairs, obfuscation passwords, and AmneziaWG wireguard endpoints
// (private keys, amnezia params, and per-peer public/preshared keys).
func ExtractCredentials(opts *option.Options) PersistedCredentials {
	creds := EmptyPersistedCredentials()

	for _, inbound := range opts.Inbounds {
		switch o := inbound.Options.(type) {
		case *option.VLESSInboundOptions:
			extractVLESSCredentials(inbound.Tag, o, &creds)
		case *option.Hysteria2InboundOptions:
			extractHysteria2Credentials(inbound.Tag, o, &creds)
		}
	}

	for _, endpoint := range opts.Endpoints {
		// endpoint.Options is any; a non-wireguard endpoint fails the type
		// assertion and is skipped. Only AmneziaWG endpoints (non-nil Amnezia)
		// are persisted — plain wireguard endpoints are skipped.
		wgOpts, ok := endpoint.Options.(*option.WireGuardEndpointOptions)
		if !ok || wgOpts.Amnezia == nil {
			continue
		}
		extractWireGuardCredentials(endpoint.Tag, wgOpts, &creds)
	}

	return creds
}

func extractVLESSCredentials(tag string, opts *option.VLESSInboundOptions, creds *PersistedCredentials) {
	users := make(map[string]UserCredentials, len(opts.Users))
	for _, u := range opts.Users {
		users[u.Name] = UserCredentials{UUID: u.UUID, Flow: u.Flow}
	}
	creds.InboundUsers[tag] = users

	if opts.TLS != nil && opts.TLS.Reality != nil && opts.TLS.Reality.Enabled {
		reality := opts.TLS.Reality
		creds.RealityKeys[tag] = RealityKeyPair{
			PrivateKey: reality.PrivateKey,
			ShortID:    []string(reality.ShortID),
		}
	}
}

func extractHysteria2Credentials(tag string, opts *option.Hysteria2InboundOptions, creds *PersistedCredentials) {
	users := make(map[string]UserCredentials, len(opts.Users))
	for _, u := range opts.Users {
		users[u.Name] = UserCredentials{Password: u.Password}
	}
	creds.InboundUsers[tag] = users

	if opts.Obfs != nil && opts.Obfs.Password != "" {
		creds.ObfsPasswords[tag] = opts.Obfs.Password
	}
}

func extractWireGuardCredentials(tag string, opts *option.WireGuardEndpointOptions, creds *PersistedCredentials) {
	peers := make(map[string]WireGuardPeerCreds, len(opts.Peers))
	for _, peer := range opts.Peers {
		if peer.PublicKey == "" {
			continue
		}
		peers[peer.PublicKey] = WireGuardPeerCreds{
			PublicKey:    peer.PublicKey,
			PresharedKey: peer.PreSharedKey,
		}
	}
	creds.WireGuardEndpoints[tag] = WireGuardEndpointCreds{
		PrivateKey: opts.PrivateKey,
		Amnezia:    cloneAmnezia(opts.Amnezia),
		Peers:      peers,
	}
}

// cloneAmnezia returns a deep copy of amnezia so persisted credentials do not
// share pointer state with the parsed options. The H1-H4 fields are pointers
// and are cloned individually; all other fields are value types.
func cloneAmnezia(amnezia *option.WireGuardAmnezia) *option.WireGuardAmnezia {
	if amnezia == nil {
		return nil
	}
	clone := *amnezia
	clone.H1 = cloneRangeUint32(amnezia.H1)
	clone.H2 = cloneRangeUint32(amnezia.H2)
	clone.H3 = cloneRangeUint32(amnezia.H3)
	clone.H4 = cloneRangeUint32(amnezia.H4)
	return &clone
}

func cloneRangeUint32(r *badoption.Range[uint32]) *badoption.Range[uint32] {
	if r == nil {
		return nil
	}
	cloned := *r
	return &cloned
}
