package links

import (
	"fmt"
	"net"
	"net/url"
	"strconv"

	"github.com/sagernet/sing-box/option"
)

const (
	defaultFingerprint = "chrome"
	securityReality    = "reality"
	securityTLS        = "tls"
	securityNone       = "none"
	transportTypeTCP   = "tcp"
)

// VLESSLink builds a vless:// share URI from the given inbound info.
func VLESSLink(info InboundInfo) string {
	params := url.Values{}
	params.Set("type", transportTypeTCP)

	switch {
	case info.Reality != nil:
		params.Set("security", securityReality)
		params.Set("sni", info.Reality.SNI)
		params.Set("fp", defaultFingerprint)
		params.Set("pbk", info.Reality.PublicKey)

		if info.Reality.ShortID != "" {
			params.Set("sid", info.Reality.ShortID)
		}
	case info.ServerName != "":
		params.Set("security", securityTLS)
		params.Set("sni", info.ServerName)
	default:
		params.Set("security", securityNone)
	}

	if info.Flow != "" {
		params.Set("flow", info.Flow)
	}

	fragment := fmt.Sprintf("%s-%s-%s", info.Server, info.Tag, info.UserName)
	hostPort := net.JoinHostPort(info.Endpoint, strconv.FormatUint(uint64(info.ListenPort), 10))

	return fmt.Sprintf(
		"vless://%s@%s?%s#%s",
		info.UUID, hostPort,
		params.Encode(), url.PathEscape(fragment),
	)
}

// VLESSOutboundJSON builds a sing-box VLESS outbound JSON config.
func VLESSOutboundJSON(info InboundInfo) (string, error) {
	tag := fmt.Sprintf("%s-%s-%s", info.Server, info.Tag, info.UserName)

	opts := option.VLESSOutboundOptions{
		ServerOptions: option.ServerOptions{
			Server:     info.Endpoint,
			ServerPort: info.ListenPort,
		},
		UUID: info.UUID,
		Flow: info.Flow,
	}

	if info.Reality != nil {
		opts.TLS = &option.OutboundTLSOptions{
			Enabled:    true,
			ServerName: info.Reality.SNI,
			UTLS: &option.OutboundUTLSOptions{
				Enabled:     true,
				Fingerprint: defaultFingerprint,
			},
			Reality: &option.OutboundRealityOptions{
				Enabled:   true,
				PublicKey: info.Reality.PublicKey,
				ShortID:   info.Reality.ShortID,
			},
		}
	} else if info.ServerName != "" {
		opts.TLS = &option.OutboundTLSOptions{
			Enabled:    true,
			ServerName: info.ServerName,
		}
	}

	return marshalOutboundJSON(inboundTypeVLESS, tag, opts)
}
