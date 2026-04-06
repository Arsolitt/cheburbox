package generate

import (
	"context"
	"fmt"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	singjson "github.com/sagernet/sing/common/json"

	"github.com/Arsolitt/cheburbox/config"
)

// ConvertDNS converts cheburbox DNS configuration to sing-box DNSOptions.
func ConvertDNS(cfg config.DNS) (*option.DNSOptions, error) {
	servers, err := convertDNSServers(cfg.Servers)
	if err != nil {
		return nil, fmt.Errorf("convert dns servers: %w", err)
	}

	opts := &option.DNSOptions{
		RawDNSOptions: option.RawDNSOptions{
			Final:   derefOrEmpty(cfg.Final),
			Servers: servers,
			DNSClientOptions: option.DNSClientOptions{
				Strategy: parseDomainStrategy(derefOrEmpty(cfg.Strategy)),
			},
		},
	}

	if len(cfg.Rules) > 0 {
		ctx := include.Context(context.Background())
		var rules []option.DNSRule
		if err := singjson.UnmarshalContext(ctx, cfg.Rules, &rules); err != nil {
			return nil, fmt.Errorf("unmarshal dns rules: %w", err)
		}
		opts.Rules = rules
	}

	return opts, nil
}

func convertDNSServers(servers []config.DNSServer) ([]option.DNSServerOptions, error) {
	result := make([]option.DNSServerOptions, 0, len(servers))

	for _, s := range servers {
		opts, err := convertDNSServer(s)
		if err != nil {
			return nil, fmt.Errorf("server %q: %w", s.Tag, err)
		}
		result = append(result, opts)
	}

	return result, nil
}

func convertDNSServer(s config.DNSServer) (option.DNSServerOptions, error) {
	var serverOpts any

	switch s.Type {
	case C.DNSTypeLocal:
		serverOpts = &option.LocalDNSServerOptions{
			RawLocalDNSServerOptions: option.RawLocalDNSServerOptions{
				DialerOptions: option.DialerOptions{
					Detour: s.Detour,
				},
			},
		}

	case C.DNSTypeUDP, C.DNSTypeTCP:
		serverOpts = &option.RemoteDNSServerOptions{
			RawLocalDNSServerOptions: option.RawLocalDNSServerOptions{
				DialerOptions: option.DialerOptions{
					Detour: s.Detour,
				},
			},
			DNSServerAddressOptions: option.DNSServerAddressOptions{
				Server:     s.Server,
				ServerPort: intToUint16(s.ServerPort),
			},
		}

	case C.DNSTypeTLS, C.DNSTypeQUIC:
		serverOpts = &option.RemoteTLSDNSServerOptions{
			RemoteDNSServerOptions: option.RemoteDNSServerOptions{
				RawLocalDNSServerOptions: option.RawLocalDNSServerOptions{
					DialerOptions: option.DialerOptions{
						Detour: s.Detour,
					},
				},
				DNSServerAddressOptions: option.DNSServerAddressOptions{
					Server:     s.Server,
					ServerPort: intToUint16(s.ServerPort),
				},
			},
		}

	case C.DNSTypeHTTPS, C.DNSTypeHTTP3:
		serverOpts = &option.RemoteHTTPSDNSServerOptions{
			RemoteTLSDNSServerOptions: option.RemoteTLSDNSServerOptions{
				RemoteDNSServerOptions: option.RemoteDNSServerOptions{
					RawLocalDNSServerOptions: option.RawLocalDNSServerOptions{
						DialerOptions: option.DialerOptions{
							Detour: s.Detour,
						},
					},
					DNSServerAddressOptions: option.DNSServerAddressOptions{
						Server:     s.Server,
						ServerPort: intToUint16(s.ServerPort),
					},
				},
			},
		}

	case C.DNSTypeDHCP:
		serverOpts = &option.DHCPDNSServerOptions{
			LocalDNSServerOptions: option.LocalDNSServerOptions{
				RawLocalDNSServerOptions: option.RawLocalDNSServerOptions{
					DialerOptions: option.DialerOptions{
						Detour: s.Detour,
					},
				},
			},
		}

	case C.DNSTypeFakeIP:
		serverOpts = &option.FakeIPDNSServerOptions{}

	default:
		return option.DNSServerOptions{}, fmt.Errorf("unsupported dns server type: %s", s.Type)
	}

	return option.DNSServerOptions{
		Type:    s.Type,
		Tag:     s.Tag,
		Options: serverOpts,
	}, nil
}

func intToUint16(v int) uint16 {
	if v < 0 || v > 65535 {
		return 0
	}
	return uint16(v)
}

func parseDomainStrategy(s string) option.DomainStrategy {
	switch s {
	case "prefer_ipv4":
		return option.DomainStrategy(C.DomainStrategyPreferIPv4)
	case "prefer_ipv6":
		return option.DomainStrategy(C.DomainStrategyPreferIPv6)
	case "ipv4_only":
		return option.DomainStrategy(C.DomainStrategyIPv4Only)
	case "ipv6_only":
		return option.DomainStrategy(C.DomainStrategyIPv6Only)
	case "as_is", "":
		return option.DomainStrategy(C.DomainStrategyAsIS)
	default:
		return option.DomainStrategy(C.DomainStrategyAsIS)
	}
}

func derefOrEmpty(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}
