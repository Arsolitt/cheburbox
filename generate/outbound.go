package generate

import (
	"fmt"
	"time"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"

	"github.com/Arsolitt/cheburbox/config"
)

// BuildOutbound converts a cheburbox Outbound to a sing-box option.Outbound.
func BuildOutbound(out config.Outbound) (option.Outbound, error) {
	switch out.Type {
	case "direct":
		return option.Outbound{
			Type:    "direct",
			Tag:     out.Tag,
			Options: &option.DirectOutboundOptions{},
		}, nil

	case "urltest":
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

	case "selector":
		return option.Outbound{
			Type: "selector",
			Tag:  out.Tag,
			Options: &option.SelectorOutboundOptions{
				Outbounds: out.Outbounds,
			},
		}, nil

	case "vless", "hysteria2":
		return option.Outbound{}, fmt.Errorf(
			"cross-server outbound type %q not supported in single-server mode",
			out.Type,
		)

	default:
		return option.Outbound{}, fmt.Errorf("unsupported outbound type %q", out.Type)
	}
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
