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
	DNS       DNS             `json:"dns"`
	Log       json.RawMessage `json:"log,omitempty"`
	Inbounds  []Inbound       `json:"inbounds,omitempty"`
	Outbounds []Outbound      `json:"outbounds,omitempty"`
	Endpoint  string          `json:"endpoint,omitempty"`
	Version   int             `json:"version"`
	Route     *Route          `json:"route,omitempty"`
}

// DNS holds the DNS configuration section.
type DNS struct {
	Final    *string         `json:"final,omitempty"`
	Strategy *string         `json:"strategy,omitempty"`
	Servers  []DNSServer     `json:"servers"`
	Rules    json.RawMessage `json:"rules,omitempty"`
}

// DNSServer represents a single DNS server entry.
type DNSServer struct {
	Type       string `json:"type"`
	Tag        string `json:"tag"`
	Server     string `json:"server,omitempty"`
	Detour     string `json:"detour,omitempty"`
	ServerPort int    `json:"server_port,omitempty"`
}

// Inbound represents a single inbound configuration.
// Use Type field to determine which fields are relevant.
type Inbound struct {
	Obfs                   *ObfsConfig       `json:"obfs,omitempty"`
	TLS                    *InboundTLS       `json:"tls,omitempty"`
	Masq                   *MasqueradeConfig `json:"masquerade,omitempty"`
	Type                   string            `json:"type"`
	Stack                  string            `json:"stack,omitempty"`
	Tag                    string            `json:"tag"`
	InterfaceName          string            `json:"interface_name,omitempty"`
	Users                  []string          `json:"users,omitempty"`
	Address                []string          `json:"address,omitempty"`
	ExcludeInterface       []string          `json:"exclude_interface,omitempty"`
	RouteExcludeAddress    []string          `json:"route_exclude_address,omitempty"`
	DownMbps               int               `json:"down_mbps,omitempty"`
	UpMbps                 int               `json:"up_mbps,omitempty"`
	MTU                    int               `json:"mtu,omitempty"`
	ListenPort             int               `json:"listen_port,omitempty"`
	AutoRoute              bool              `json:"auto_route,omitempty"`
	EndpointIndependentNAT bool              `json:"endpoint_independent_nat,omitempty"`
}

// InboundTLS holds TLS configuration for an inbound.
type InboundTLS struct {
	Reality    *RealityConfig `json:"reality,omitempty"`
	ServerName string         `json:"server_name,omitempty"`
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

// Outbound represents a single outbound configuration.
// Use Type field to determine which fields are relevant.
type Outbound struct {
	Type      string   `json:"type"`
	Tag       string   `json:"tag"`
	Server    string   `json:"server,omitempty"`
	Inbound   string   `json:"inbound,omitempty"`
	User      string   `json:"user,omitempty"`
	Flow      string   `json:"flow,omitempty"`
	Endpoint  string   `json:"endpoint,omitempty"`
	URL       string   `json:"url,omitempty"`
	Interval  string   `json:"interval,omitempty"`
	Outbounds []string `json:"outbounds,omitempty"`
}

// Route holds the routing configuration section.
type Route struct {
	Final               string          `json:"final,omitempty"`
	RuleSets            json.RawMessage `json:"rule_sets,omitempty"`
	CustomRuleSets      []string        `json:"custom_rule_sets,omitempty"`
	Rules               json.RawMessage `json:"rules,omitempty"`
	AutoDetectInterface bool            `json:"auto_detect_interface,omitempty"`
}
