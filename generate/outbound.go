package generate

import (
	"encoding/base64"
	"fmt"
	"time"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"

	"github.com/Arsolitt/cheburbox/config"
)

const outboundTypeDirect = "direct"

// OutboundBuildOption configures outbound building behavior.
type OutboundBuildOption func(*outboundBuildConfig)

type outboundBuildConfig struct {
	defaultUser string
}

// WithDefaultUser sets a fallback user for cross-server outbounds
// when no explicit user is specified in the config.
func WithDefaultUser(user string) OutboundBuildOption {
	return func(c *outboundBuildConfig) {
		c.defaultUser = user
	}
}

// BuildOutbound converts a cheburbox Outbound to a sing-box option.Outbound.
func BuildOutbound(out config.Outbound) (option.Outbound, error) {
	return BuildOutboundWithState(out, nil)
}

// BuildOutboundWithState converts a cheburbox Outbound to a sing-box option.Outbound
// using the provided ServerState for cross-server credential resolution.
func BuildOutboundWithState(
	out config.Outbound,
	state *ServerState,
	opts ...OutboundBuildOption,
) (option.Outbound, error) {
	var cfg outboundBuildConfig
	for _, opt := range opts {
		opt(&cfg)
	}

	switch out.Type {
	case outboundTypeDirect:
		return buildDirectOutbound(out)
	case "urltest":
		return buildURLTestOutbound(out)
	case "selector":
		return buildSelectorOutbound(out)
	case inboundTypeVLESS:
		return buildCrossServerVlessOutbound(out, state, cfg)
	case inboundTypeHysteria2:
		return buildCrossServerHysteria2Outbound(out, state, cfg)
	default:
		return option.Outbound{}, fmt.Errorf("unsupported outbound type %q", out.Type)
	}
}

func buildDirectOutbound(out config.Outbound) (option.Outbound, error) {
	opts := option.DirectOutboundOptions{}
	if out.DomainResolver != "" {
		opts.DomainResolver = &option.DomainResolveOptions{
			Server: out.DomainResolver,
		}
	}

	return option.Outbound{
		Type:    outboundTypeDirect,
		Tag:     out.Tag,
		Options: &opts,
	}, nil
}

func buildURLTestOutbound(out config.Outbound) (option.Outbound, error) {
	interval, err := parseInterval(out.Interval)
	if err != nil {
		return option.Outbound{}, fmt.Errorf("parse urltest interval: %w", err)
	}

	return option.Outbound{
		Type: "urltest",
		Tag:  out.Tag,
		Options: &option.URLTestOutboundOptions{
			Outbounds: out.Outbounds,
			URL:       out.URL,
			Interval:  interval,
		},
	}, nil
}

func buildSelectorOutbound(out config.Outbound) (option.Outbound, error) {
	return option.Outbound{
		Type: "selector",
		Tag:  out.Tag,
		Options: &option.SelectorOutboundOptions{
			Outbounds: out.Outbounds,
		},
	}, nil
}

func buildCrossServerVlessOutbound(
	out config.Outbound,
	state *ServerState,
	cfg outboundBuildConfig,
) (option.Outbound, error) {
	if state == nil {
		return option.Outbound{}, fmt.Errorf("cross-server outbound %q requires server state", out.Tag)
	}

	creds, ok := state.GetInboundCredentials(out.Server, out.Inbound)
	if !ok {
		return option.Outbound{}, fmt.Errorf(
			"server %q inbound %q: no credentials found",
			out.Server, out.Inbound,
		)
	}

	user := resolveUser(out.User, cfg.defaultUser)
	if user == "" {
		return option.Outbound{}, fmt.Errorf("outbound %q: no user specified", out.Tag)
	}

	userCreds, ok := creds.Users[user]
	if !ok {
		return option.Outbound{}, fmt.Errorf(
			"server %q inbound %q: user %q not found",
			out.Server, out.Inbound, user,
		)
	}

	host, err := resolveEndpoint(out, state)
	if err != nil {
		return option.Outbound{}, fmt.Errorf("resolve endpoint: %w", err)
	}

	port, _ := state.GetListenPort(out.Server, out.Inbound)

	opts := option.VLESSOutboundOptions{
		ServerOptions: option.ServerOptions{
			Server:     host,
			ServerPort: port,
		},
		UUID: userCreds.UUID,
		Flow: out.Flow,
	}

	if creds.Reality != nil {
		opts.TLS = &option.OutboundTLSOptions{
			Enabled: true,
			Reality: &option.OutboundRealityOptions{
				Enabled:   true,
				PublicKey: creds.Reality.PublicKey,
				ShortID:   firstShortID(creds.Reality.ShortID),
			},
		}
	}

	return option.Outbound{
		Type:    inboundTypeVLESS,
		Tag:     out.Tag,
		Options: &opts,
	}, nil
}

func buildCrossServerHysteria2Outbound(
	out config.Outbound,
	state *ServerState,
	cfg outboundBuildConfig,
) (option.Outbound, error) {
	if state == nil {
		return option.Outbound{}, fmt.Errorf("cross-server outbound %q requires server state", out.Tag)
	}

	creds, ok := state.GetInboundCredentials(out.Server, out.Inbound)
	if !ok {
		return option.Outbound{}, fmt.Errorf(
			"server %q inbound %q: no credentials found",
			out.Server, out.Inbound,
		)
	}

	user := resolveUser(out.User, cfg.defaultUser)
	if user == "" {
		return option.Outbound{}, fmt.Errorf("outbound %q: no user specified", out.Tag)
	}

	userCreds, ok := creds.Users[user]
	if !ok {
		return option.Outbound{}, fmt.Errorf(
			"server %q inbound %q: user %q not found",
			out.Server, out.Inbound, user,
		)
	}

	host, err := resolveEndpoint(out, state)
	if err != nil {
		return option.Outbound{}, fmt.Errorf("resolve endpoint: %w", err)
	}

	port, _ := state.GetListenPort(out.Server, out.Inbound)

	opts := option.Hysteria2OutboundOptions{
		ServerOptions: option.ServerOptions{
			Server:     host,
			ServerPort: port,
		},
		Password: userCreds.Password,
		OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{
			TLS: &option.OutboundTLSOptions{
				Enabled: true,
			},
		},
	}

	if creds.ObfsPassword != "" {
		opts.Obfs = &option.Hysteria2Obfs{
			Type:     "salamander",
			Password: creds.ObfsPassword,
		}
	}

	pin, hasPin := state.GetPinSHA256(out.Server, out.Inbound)
	if hasPin {
		rawBytes, decodeErr := decodePinSHA256(pin)
		if decodeErr != nil {
			return option.Outbound{}, fmt.Errorf("decode pin-sha256: %w", decodeErr)
		}
		opts.TLS.CertificatePublicKeySHA256 = badoption.Listable[[]byte]{rawBytes}
	}

	return option.Outbound{
		Type:    inboundTypeHysteria2,
		Tag:     out.Tag,
		Options: &opts,
	}, nil
}

func resolveEndpoint(out config.Outbound, state *ServerState) (string, error) {
	ep := out.Endpoint
	if ep == "" {
		var ok bool
		ep, ok = state.GetEndpoint(out.Server)
		if !ok {
			return "", fmt.Errorf("server %q has no endpoint configured", out.Server)
		}
	}

	return ep, nil
}

func resolveUser(explicitUser string, defaultUser string) string {
	if explicitUser != "" {
		return explicitUser
	}
	return defaultUser
}

func firstShortID(ids []string) string {
	if len(ids) == 0 {
		return ""
	}
	return ids[0]
}

func decodePinSHA256(pin string) ([]byte, error) {
	const prefix = "sha256/"
	if len(pin) <= len(prefix) {
		return nil, fmt.Errorf("invalid pin format %q", pin)
	}

	decoded, err := base64.RawURLEncoding.DecodeString(pin[len(prefix):])
	if err != nil {
		return nil, fmt.Errorf("decode base64: %w", err)
	}

	return decoded, nil
}

func parseInterval(s string) (badoption.Duration, error) {
	if s == "" {
		return 0, nil
	}

	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("invalid duration %q: %w", s, err)
	}

	return badoption.Duration(d), nil
}
