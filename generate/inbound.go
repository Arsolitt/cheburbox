package generate

import (
	"errors"
	"fmt"
	"net/netip"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"

	"github.com/Arsolitt/cheburbox/config"
)

// InboundCredentials holds resolved credentials for building inbound options.
type InboundCredentials struct {
	Users        map[string]UserCreds
	Reality      *RealityKeys
	ObfsPassword string
}

// UserCreds holds per-user credentials.
type UserCreds struct {
	UUID     string
	Password string
}

// RealityKeys holds generated reality key pair and short IDs.
type RealityKeys struct {
	PrivateKey string
	PublicKey  string
	ShortID    []string
}

// vlessInboundOptions mirrors option.VLESSInboundOptions for type assertions in tests.
type vlessInboundOptions = option.VLESSInboundOptions

// hysteria2InboundOptions mirrors option.Hysteria2InboundOptions for type assertions in tests.
type hysteria2InboundOptions = option.Hysteria2InboundOptions

// tunInboundOptions mirrors option.TunInboundOptions for type assertions in tests.
type tunInboundOptions = option.TunInboundOptions

// BuildInbound converts a cheburbox Inbound config and resolved credentials into a sing-box Inbound option.
func BuildInbound(in config.Inbound, creds InboundCredentials) (option.Inbound, error) {
	switch in.Type {
	case "vless":
		return buildVLESSInbound(in, creds)
	case "hysteria2":
		return buildHysteria2Inbound(in, creds)
	case "tun":
		return buildTunInbound(in)
	default:
		return option.Inbound{}, fmt.Errorf("unknown inbound type: %s", in.Type)
	}
}

func buildVLESSInbound(in config.Inbound, creds InboundCredentials) (option.Inbound, error) {
	users := buildVLESSUsers(creds)
	if len(users) == 0 && len(in.Users) > 0 {
		return option.Inbound{}, errors.New("missing credentials for declared users")
	}

	opts := option.VLESSInboundOptions{
		ListenOptions: option.ListenOptions{
			ListenPort: intToUint16(in.ListenPort),
		},
		Users: users,
	}

	if in.TLS != nil {
		opts.InboundTLSOptionsContainer.TLS = buildInboundTLS(in.TLS, creds)
	}

	return option.Inbound{
		Type:    in.Type,
		Tag:     in.Tag,
		Options: &opts,
	}, nil
}

func buildVLESSUsers(creds InboundCredentials) []option.VLESSUser {
	if len(creds.Users) == 0 {
		return nil
	}

	users := make([]option.VLESSUser, 0, len(creds.Users))
	for name, uc := range creds.Users {
		users = append(users, option.VLESSUser{
			Name: name,
			UUID: uc.UUID,
		})
	}

	return users
}

func buildInboundTLS(tls *config.InboundTLS, creds InboundCredentials) *option.InboundTLSOptions {
	tlsOpts := &option.InboundTLSOptions{
		ServerName: tls.ServerName,
	}

	if tls.Reality != nil && creds.Reality != nil {
		tlsOpts.Reality = &option.InboundRealityOptions{
			Enabled:    true,
			PrivateKey: creds.Reality.PrivateKey,
			ShortID:    badoption.Listable[string](creds.Reality.ShortID),
			Handshake: option.InboundRealityHandshakeOptions{
				ServerOptions: option.ServerOptions{
					Server:     tls.Reality.Handshake.Server,
					ServerPort: intToUint16(tls.Reality.Handshake.ServerPort),
				},
			},
		}
	}

	return tlsOpts
}

func buildHysteria2Inbound(in config.Inbound, creds InboundCredentials) (option.Inbound, error) {
	users := buildHysteria2Users(creds)
	if len(users) == 0 && len(in.Users) > 0 {
		return option.Inbound{}, errors.New("missing credentials for declared users")
	}

	opts := option.Hysteria2InboundOptions{
		ListenOptions: option.ListenOptions{
			ListenPort: intToUint16(in.ListenPort),
		},
		UpMbps:   in.UpMbps,
		DownMbps: in.DownMbps,
		Users:    users,
	}

	if in.Obfs != nil {
		pw := in.Obfs.Password
		if pw == "" {
			pw = creds.ObfsPassword
		}
		opts.Obfs = &option.Hysteria2Obfs{
			Type:     in.Obfs.Type,
			Password: pw,
		}
	}

	if in.TLS != nil {
		opts.InboundTLSOptionsContainer.TLS = &option.InboundTLSOptions{
			ServerName: in.TLS.ServerName,
		}
	}

	if in.Masq != nil {
		masq, masqErr := buildHysteria2Masquerade(in.Masq)
		if masqErr != nil {
			return option.Inbound{}, masqErr
		}
		opts.Masquerade = masq
	}

	return option.Inbound{
		Type:    in.Type,
		Tag:     in.Tag,
		Options: &opts,
	}, nil
}

func buildHysteria2Users(creds InboundCredentials) []option.Hysteria2User {
	if len(creds.Users) == 0 {
		return nil
	}

	users := make([]option.Hysteria2User, 0, len(creds.Users))
	for name, uc := range creds.Users {
		users = append(users, option.Hysteria2User{
			Name:     name,
			Password: uc.Password,
		})
	}

	return users
}

func buildHysteria2Masquerade(masq *config.MasqueradeConfig) (*option.Hysteria2Masquerade, error) {
	m := &option.Hysteria2Masquerade{
		Type: masq.Type,
	}

	switch masq.Type {
	case "proxy":
		m.ProxyOptions = option.Hysteria2MasqueradeProxy{
			URL:         masq.URL,
			RewriteHost: masq.RewriteHost,
		}
	default:
		return nil, fmt.Errorf("unsupported masquerade type: %s", masq.Type)
	}

	return m, nil
}

func buildTunInbound(in config.Inbound) (option.Inbound, error) {
	addrs, err := parsePrefixes(in.Address, "address")
	if err != nil {
		return option.Inbound{}, err
	}

	routeExcludeAddrs, err := parsePrefixes(in.RouteExcludeAddress, "route exclude address")
	if err != nil {
		return option.Inbound{}, err
	}

	opts := option.TunInboundOptions{
		InterfaceName:          in.InterfaceName,
		MTU:                    intToUint32(in.MTU),
		Address:                badoption.Listable[netip.Prefix](addrs),
		AutoRoute:              in.AutoRoute,
		Stack:                  in.Stack,
		EndpointIndependentNat: in.EndpointIndependentNAT,
		ExcludeInterface:       badoption.Listable[string](in.ExcludeInterface),
		RouteExcludeAddress:    badoption.Listable[netip.Prefix](routeExcludeAddrs),
	}

	return option.Inbound{
		Type:    in.Type,
		Tag:     in.Tag,
		Options: &opts,
	}, nil
}

func parsePrefixes(strs []string, field string) ([]netip.Prefix, error) {
	if len(strs) == 0 {
		return nil, nil
	}

	prefixes := make([]netip.Prefix, 0, len(strs))
	for _, s := range strs {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return nil, fmt.Errorf("parse %s %q: %w", field, s, err)
		}
		prefixes = append(prefixes, p)
	}

	return prefixes, nil
}

func intToUint32(v int) uint32 {
	if v < 0 {
		return 0
	}
	//nolint:gosec // G115: range already checked above.
	return uint32(v)
}
