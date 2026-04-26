package links

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
)

const (
	hysteria2Scheme  = "hysteria2"
	hysteria2ALPNSep = ","
	pinSHA256Prefix  = "sha256/"
)

// Hysteria2Link builds a hysteria2:// share URI from the given inbound info.
func Hysteria2Link(info InboundInfo) string {
	u := url.URL{
		Scheme:   hysteria2Scheme,
		User:     url.User(info.Password),
		Host:     info.Endpoint + ":" + strconv.FormatUint(uint64(info.ListenPort), 10),
		Fragment: info.Server + "-" + info.Tag + "-" + info.UserName,
	}

	query := url.Values{}

	if info.ServerName != "" {
		query.Set("sni", info.ServerName)
	}

	if info.ObfsType != "" {
		query.Set("obfs", info.ObfsType)
		query.Set("obfs-password", info.ObfsPassword)
	}

	if info.PinSHA256 != "" {
		query.Set("pinSHA256", info.PinSHA256)
	}

	if len(info.ALPN) > 0 {
		query.Set("alpn", strings.Join(info.ALPN, hysteria2ALPNSep))
	}

	u.RawQuery = query.Encode()

	return u.String()
}

// Hysteria2OutboundJSON builds a sing-box Hysteria2 outbound JSON config.
func Hysteria2OutboundJSON(info InboundInfo) (string, error) {
	tag := info.Server + "-" + info.Tag + "-" + info.UserName

	tlsOpts := &option.OutboundTLSOptions{
		Enabled: true,
		ALPN:    badoption.Listable[string]{"h3"},
	}

	if info.ServerName != "" {
		tlsOpts.ServerName = info.ServerName
	}

	if info.PinSHA256 != "" {
		rawBytes, err := decodePinSHA256(info.PinSHA256)
		if err != nil {
			return "", fmt.Errorf("decode pin-sha256: %w", err)
		}

		tlsOpts.CertificatePublicKeySHA256 = badoption.Listable[[]byte]{rawBytes}
	}

	opts := option.Hysteria2OutboundOptions{
		ServerOptions: option.ServerOptions{
			Server:     info.Endpoint,
			ServerPort: info.ListenPort,
		},
		Password: info.Password,
		OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{
			TLS: tlsOpts,
		},
	}

	if info.ObfsType != "" {
		opts.Obfs = &option.Hysteria2Obfs{
			Type:     info.ObfsType,
			Password: info.ObfsPassword,
		}
	}

	return marshalOutboundJSON(inboundTypeHysteria2, tag, opts)
}

// decodePinSHA256 decodes a "sha256/<base64url>" pin string into raw bytes.
func decodePinSHA256(pin string) ([]byte, error) {
	if len(pin) <= len(pinSHA256Prefix) {
		return nil, fmt.Errorf("invalid pin format %q", pin)
	}

	decoded, err := base64.RawURLEncoding.DecodeString(pin[len(pinSHA256Prefix):])
	if err != nil {
		return nil, fmt.Errorf("decode base64: %w", err)
	}

	return decoded, nil
}
