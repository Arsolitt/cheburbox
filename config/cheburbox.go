// Package config defines cheburbox.json schema types and provides loading,
// discovery, and validation for server configurations.
package config

import "encoding/json"

// CurrentSchemaVersion is the only supported cheburbox.json schema version.
const CurrentSchemaVersion = 1

// Config is the top-level cheburbox.json configuration.
//
//nolint:govet // fieldalignment: 8-byte savings negligible for a config struct loaded once.
type Config struct {
	DNS          DNS             `json:"dns"`
	Log          json.RawMessage `json:"log,omitempty"`
	Inbounds     []Inbound       `json:"inbounds,omitempty"`
	Outbounds    []Outbound      `json:"outbounds,omitempty"`
	Endpoint     string          `json:"endpoint,omitempty"`
	Version      int             `json:"version"`
	Route        *Route          `json:"route,omitempty"`
	Experimental *Experimental   `json:"experimental,omitempty"`
}

// Experimental holds optional experimental sing-box settings.
type Experimental struct {
	CacheFile *CacheFileConfig `json:"cache_file,omitempty"`
}

// CacheFileConfig controls the sing-box cache_file feature.
type CacheFileConfig struct {
	Enabled *bool `json:"enabled,omitempty"`
}

// DNS holds the DNS configuration section.
type DNS struct {
	Final         *string         `json:"final,omitempty"`
	Strategy      *string         `json:"strategy,omitempty"`
	CacheCapacity *uint32         `json:"cache_capacity,omitempty"`
	Servers       []DNSServer     `json:"servers"`
	Rules         json.RawMessage `json:"rules,omitempty"`
}

// DNSServer represents a single DNS server entry.
type DNSServer struct {
	Type       string `json:"type"`
	Tag        string `json:"tag"`
	Server     string `json:"server,omitempty"`
	Detour     string `json:"detour,omitempty"`
	ServerPort int    `json:"server_port,omitempty"`
}

// InboundUser represents a user declaration on an inbound.
// Name is required. Flow is optional and only used for VLESS inbounds.
type InboundUser struct {
	Name string `json:"name"`
	Flow string `json:"flow,omitempty"`
}

// UserName returns a slice of user names from InboundUser entries.
func UserName(users []InboundUser) []string {
	names := make([]string, len(users))
	for i, u := range users {
		names[i] = u.Name
	}
	return names
}

// Inbound represents a single inbound configuration.
// Use Type field to determine which fields are relevant.
type Inbound struct {
	Amnezia                *AmneziaConfig    `json:"amnezia,omitempty"`
	Obfs                   *ObfsConfig       `json:"obfs,omitempty"`
	TLS                    *InboundTLS       `json:"tls,omitempty"`
	Masq                   *MasqueradeConfig `json:"masquerade,omitempty"`
	Multiplex              *InboundMultiplex `json:"multiplex,omitempty"`
	Type                   string            `json:"type"`
	Stack                  string            `json:"stack,omitempty"`
	Tag                    string            `json:"tag"`
	Listen                 string            `json:"listen,omitempty"`
	InterfaceName          string            `json:"interface_name,omitempty"`
	ExcludeInterface       []string          `json:"exclude_interface,omitempty"`
	Address                []string          `json:"address,omitempty"`
	Users                  []InboundUser     `json:"users,omitempty"`
	RouteExcludeAddress    []string          `json:"route_exclude_address,omitempty"`
	DownMbps               int               `json:"down_mbps,omitempty"`
	UpMbps                 int               `json:"up_mbps,omitempty"`
	MTU                    int               `json:"mtu,omitempty"`
	ListenPort             int               `json:"listen_port,omitempty"`
	IPRoute2TableIndex     int               `json:"iproute2_table_index,omitempty"`
	IPRoute2RuleIndex      int               `json:"iproute2_rule_index,omitempty"`
	AutoRoute              bool              `json:"auto_route,omitempty"`
	AutoRedirect           bool              `json:"auto_redirect,omitempty"`
	StrictRoute            bool              `json:"strict_route,omitempty"`
	EndpointIndependentNAT bool              `json:"endpoint_independent_nat,omitempty"`
}

// InboundTLS holds TLS configuration for an inbound.
type InboundTLS struct {
	Reality    *RealityConfig `json:"reality,omitempty"`
	ServerName string         `json:"server_name,omitempty"`
	ALPN       []string       `json:"alpn,omitempty"`
}

// RealityConfig holds TLS reality configuration for VLESS inbounds.
type RealityConfig struct {
	Handshake *RealityHandshake `json:"handshake"`
	ShortID   []string          `json:"short_id,omitempty"`
}

// RealityHandshake holds the handshake server details for reality.
type RealityHandshake struct {
	Server     string `json:"server"`
	ServerPort int    `json:"server_port"`
}

// ObfsConfig holds obfuscation configuration for hysteria2.
type ObfsConfig struct {
	Type     string `json:"type"`
	Password string `json:"password,omitempty"`
}

// MasqueradeConfig holds masquerade configuration for hysteria2.
type MasqueradeConfig struct {
	Type        string `json:"type"`
	URL         string `json:"url,omitempty"`
	RewriteHost bool   `json:"rewrite_host,omitempty"`
}

// AmneziaConfig holds AmneziaWG obfuscation preferences. Protocol, Preset, and
// MTU are user-facing; the actual Jc/S1/H1/I1 parameters are produced by
// amnezigo (from the named preset or, when Preset is empty, fully random) and
// persisted in config.json so they stay stable across runs.
type AmneziaConfig struct {
	Protocol string `json:"protocol,omitempty"` // quic|dns|dtls|stun|sip|rtp|random; default quic
	Preset   string `json:"preset,omitempty"`   // amnezigo preset name; empty → random params
	MTU      int    `json:"mtu,omitempty"`      // default 1280
}

// InboundMultiplex holds sing-box multiplex (mux) configuration for VLESS
// inbounds. It mirrors sing-box InboundMultiplexOptions: the server accepts
// whichever protocol the client selects, so no protocol field is present.
type InboundMultiplex struct {
	Brutal  *BrutalConfig `json:"brutal,omitempty"`
	Enabled bool          `json:"enabled,omitempty"`
	Padding bool          `json:"padding,omitempty"`
}

// OutboundMultiplex holds sing-box multiplex (mux) configuration for VLESS
// outbounds. It mirrors sing-box OutboundMultiplexOptions: the client selects
// the protocol and connection/stream limits. Protocol must be one of the
// sing-box mux protocols (h2mux, smux, yamux); empty defaults to h2mux.
type OutboundMultiplex struct {
	Brutal         *BrutalConfig `json:"brutal,omitempty"`
	Protocol       string        `json:"protocol,omitempty"`
	MaxConnections int           `json:"max_connections,omitempty"`
	MinStreams     int           `json:"min_streams,omitempty"`
	MaxStreams     int           `json:"max_streams,omitempty"`
	Enabled        bool          `json:"enabled,omitempty"`
	Padding        bool          `json:"padding,omitempty"`
}

// BrutalConfig holds TCP Brutal congestion-control configuration for multiplex.
// It mirrors sing-box BrutalOptions and only takes effect when the multiplex
// brutal block is enabled.
type BrutalConfig struct {
	Enabled  bool `json:"enabled,omitempty"`
	UpMbps   int  `json:"up_mbps,omitempty"`
	DownMbps int  `json:"down_mbps,omitempty"`
}

// Outbound represents a single outbound configuration.
// Use Type field to determine which fields are relevant.
type Outbound struct {
	Multiplex                 *OutboundMultiplex `json:"multiplex,omitempty"`
	URL                       string             `json:"url,omitempty"`
	IdleTimeout               string             `json:"idle_timeout,omitempty"`
	Inbound                   string             `json:"inbound,omitempty"`
	Endpoint                  string             `json:"endpoint,omitempty"`
	Flow                      string             `json:"flow,omitempty"`
	DomainResolver            string             `json:"domain_resolver,omitempty"`
	Interval                  string             `json:"interval,omitempty"`
	Type                      string             `json:"type"`
	Server                    string             `json:"server,omitempty"`
	Tag                       string             `json:"tag"`
	User                      string             `json:"user,omitempty"`
	Delay                     string             `json:"delay,omitempty"`
	Strategy                  string             `json:"strategy,omitempty"`
	BlacklistTimeout          string             `json:"blacklist_timeout,omitempty"`
	Address                   []string           `json:"address,omitempty"`
	Outbounds                 []string           `json:"outbounds,omitempty"`
	MTU                       int                `json:"mtu,omitempty"`
	Tolerance                 uint16             `json:"tolerance,omitempty"`
	InterruptExistConnections bool               `json:"interrupt_exist_connections,omitempty"`
}

// Route holds the routing configuration section.
type Route struct {
	Final                 string          `json:"final,omitempty"`
	DefaultDomainResolver string          `json:"default_domain_resolver,omitempty"`
	RuleSets              json.RawMessage `json:"rule_sets,omitempty"`
	CustomRuleSets        []string        `json:"custom_rule_sets,omitempty"`
	Rules                 json.RawMessage `json:"rules,omitempty"`
	AutoDetectInterface   bool            `json:"auto_detect_interface,omitempty"`
}
