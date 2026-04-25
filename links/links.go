// Package links generates share links and JSON outbound configs from
// generated sing-box configurations and cheburbox schemas.
package links

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/Arsolitt/cheburbox/config"
	"github.com/Arsolitt/cheburbox/generate"
)

// readPinSHA256 reads the certificate file for a hysteria2 inbound and
// computes the SHA-256 pin. Returns an empty string if the cert file
// does not exist yet.
func readPinSHA256(serverDir string, serverName string, tag string) (string, error) {
	certPath := filepath.Join(serverDir, "certs", serverName+".crt")

	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}

		return "", fmt.Errorf("read cert for pin-sha256 %q: %w", tag, err)
	}

	pin, err := generate.ComputePinSHA256(certPEM)
	if err != nil {
		return "", fmt.Errorf("compute pin-sha256 for %q: %w", tag, err)
	}

	return pin, nil
}

const (
	inboundTypeVLESS     = "vless"
	inboundTypeHysteria2 = "hysteria2"
)

// Format specifies the output format for generated links.
type Format string

const (
	// FormatURI produces protocol share URIs (vless://, hysteria2://).
	FormatURI Format = "uri"
	// FormatJSON produces sing-box outbound JSON configs.
	FormatJSON Format = "json"
)

// Filter restricts which links are generated.
type Filter struct {
	Server  string
	User    string
	Inbound string
}

// InboundInfo holds all data needed to build a share link for one user on one inbound.
//
//nolint:govet // fieldalignment: config struct loaded once, clarity over packing.
type InboundInfo struct {
	// Common fields.
	Server     string
	Endpoint   string
	Tag        string
	Type       string // "vless" or "hysteria2".
	ListenPort uint16
	UserName   string
	// VLESS-specific.
	UUID    string
	Flow    string
	Reality *RealityInfo
	// Hysteria2-specific.
	Password     string
	PinSHA256    string
	ObfsType     string
	ObfsPassword string
	// Common TLS.
	ServerName string
	ALPN       []string
}

// RealityInfo holds VLESS Reality TLS parameters.
type RealityInfo struct {
	PublicKey string
	ShortID   string
	SNI       string
}

// CollectInboundInfos gathers link data for all matching server/inbound/user
// combinations under projectRoot.
func CollectInboundInfos(projectRoot string, jpath string, filter Filter) ([]InboundInfo, error) {
	servers, err := config.Discover(projectRoot)
	if err != nil {
		return nil, fmt.Errorf("discover servers: %w", err)
	}

	if filter.Server != "" {
		servers = filterServers(servers, filter.Server)
		if len(servers) == 0 {
			return nil, fmt.Errorf("server %q not found in project", filter.Server)
		}
	}

	var infos []InboundInfo

	for _, server := range servers {
		serverDir := filepath.Join(projectRoot, server)

		collected, err := collectServerInfos(serverDir, jpath, server, filter)
		if err != nil {
			return nil, fmt.Errorf("collect infos for server %q: %w", server, err)
		}

		infos = append(infos, collected...)
	}

	return infos, nil
}

// GenerateLinks produces share links or JSON outbound configs for all
// matching inbounds.
func GenerateLinks(projectRoot string, jpath string, filter Filter, format Format) ([]string, error) {
	infos, err := CollectInboundInfos(projectRoot, jpath, filter)
	if err != nil {
		return nil, fmt.Errorf("collect inbound infos: %w", err)
	}

	results := make([]string, 0, len(infos))

	for _, info := range infos {
		link, err := formatInboundInfo(info, format)
		if err != nil {
			return nil, fmt.Errorf("format link for %s/%s/%s: %w", info.Server, info.Tag, info.UserName, err)
		}

		results = append(results, link)
	}

	return results, nil
}

func filterServers(servers []string, name string) []string {
	for _, s := range servers {
		if s == name {
			return []string{s}
		}
	}

	return nil
}

func collectServerInfos(
	serverDir string,
	jpath string,
	server string,
	filter Filter,
) ([]InboundInfo, error) {
	cfg, err := config.LoadServerWithJsonnet(serverDir, jpath)
	if err != nil {
		return nil, fmt.Errorf("load config: %w", err)
	}

	configPath := filepath.Join(serverDir, "config.json")

	creds, err := config.LoadPersistedCredentials(configPath)
	if err != nil {
		return nil, fmt.Errorf("load credentials: %w", err)
	}

	var infos []InboundInfo

	for _, in := range cfg.Inbounds {
		if in.Type != inboundTypeVLESS && in.Type != inboundTypeHysteria2 {
			continue
		}

		if filter.Inbound != "" && in.Tag != filter.Inbound {
			continue
		}

		users, ok := creds.InboundUsers[in.Tag]
		if !ok {
			continue
		}

		for userName, userCreds := range users {
			if filter.User != "" && userName != filter.User {
				continue
			}

			info, err := buildInboundInfo(serverDir, cfg, in, server, userName, userCreds, creds)
			if err != nil {
				return nil, fmt.Errorf("build info for %s/%s: %w", in.Tag, userName, err)
			}

			infos = append(infos, info)
		}
	}

	return infos, nil
}

func buildInboundInfo(
	serverDir string,
	cfg config.Config,
	in config.Inbound,
	server string,
	userName string,
	userCreds config.UserCredentials,
	creds config.PersistedCredentials,
) (InboundInfo, error) {
	info := InboundInfo{
		Server:     server,
		Endpoint:   cfg.Endpoint,
		Tag:        in.Tag,
		Type:       in.Type,
		ListenPort: uint16(in.ListenPort), //nolint:gosec // validated by config.Validate (0-65535).
		UserName:   userName,
	}

	switch in.Type {
	case inboundTypeVLESS:
		info.UUID = userCreds.UUID
		info.Flow = userCreds.Flow

		if err := populateVLESSReality(&info, in, creds); err != nil {
			return InboundInfo{}, err
		}
	case inboundTypeHysteria2:
		info.Password = userCreds.Password

		if err := populateHysteria2Fields(&info, serverDir, in, creds); err != nil {
			return InboundInfo{}, err
		}
	}

	return info, nil
}

func populateVLESSReality(info *InboundInfo, in config.Inbound, creds config.PersistedCredentials) error {
	if in.TLS == nil || in.TLS.Reality == nil {
		return nil
	}

	realityKeys, ok := creds.RealityKeys[in.Tag]
	if !ok {
		return fmt.Errorf("reality keys not found for inbound %q", in.Tag)
	}

	publicKey, err := generate.DerivePublicKey(realityKeys.PrivateKey)
	if err != nil {
		return fmt.Errorf("derive reality public key for %q: %w", in.Tag, err)
	}

	ri := &RealityInfo{
		PublicKey: publicKey,
	}

	if len(realityKeys.ShortID) > 0 {
		ri.ShortID = realityKeys.ShortID[0]
	}

	if in.TLS.Reality.Handshake != nil {
		ri.SNI = in.TLS.Reality.Handshake.Server
		info.ServerName = in.TLS.Reality.Handshake.Server
	}

	info.Reality = ri

	return nil
}

func populateHysteria2Fields(
	info *InboundInfo,
	serverDir string,
	in config.Inbound,
	creds config.PersistedCredentials,
) error {
	if in.TLS != nil {
		info.ServerName = in.TLS.ServerName
		info.ALPN = in.TLS.ALPN
	}

	if in.TLS != nil && in.TLS.ServerName != "" {
		pin, err := readPinSHA256(serverDir, in.TLS.ServerName, in.Tag)
		if err != nil {
			return err
		}

		info.PinSHA256 = pin
	}

	if in.Obfs != nil {
		info.ObfsType = in.Obfs.Type

		if obfsPass, ok := creds.ObfsPasswords[in.Tag]; ok {
			info.ObfsPassword = obfsPass
		}
	}

	return nil
}

func formatInboundInfo(info InboundInfo, format Format) (string, error) {
	switch info.Type {
	case inboundTypeVLESS:
		return formatVLESS(info, format)
	case inboundTypeHysteria2:
		return formatHysteria2(info, format)
	default:
		return "", fmt.Errorf("unsupported inbound type %q", info.Type)
	}
}

func formatVLESS(info InboundInfo, format Format) (string, error) {
	switch format {
	case FormatURI:
		return VLESSLink(info), nil
	case FormatJSON:
		return VLESSOutboundJSON(info)
	default:
		return "", fmt.Errorf("unsupported format %q", format)
	}
}

func formatHysteria2(info InboundInfo, format Format) (string, error) {
	switch format {
	case FormatURI:
		return Hysteria2Link(info), nil
	case FormatJSON:
		return Hysteria2OutboundJSON(info)
	default:
		return "", fmt.Errorf("unsupported format %q", format)
	}
}
