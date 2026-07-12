package generate

// Protocol type strings for inbounds and outbounds, shared between config
// generation and validation to keep the literal values in one place.
const (
	// TypeVLESS is the VLESS inbound and cross-server outbound protocol type.
	TypeVLESS = "vless"
	// TypeHysteria2 is the hysteria2 inbound and cross-server outbound protocol type.
	TypeHysteria2 = "hysteria2"
	// TypeTun is the tun inbound protocol type.
	TypeTun = "tun"
	// TypeAmneziaWG is the AmneziaWG inbound and cross-server outbound protocol type.
	TypeAmneziaWG = "amneziawg"
	// TypeDirect is the direct outbound protocol type.
	TypeDirect = "direct"
	// TypeURLTest is the urltest outbound group protocol type.
	TypeURLTest = "urltest"
	// TypeSelector is the selector outbound group protocol type.
	TypeSelector = "selector"
	// TypeFallback is the fallback outbound group protocol type (sing-box-extended).
	TypeFallback = "fallback"
	// TypeFailover is the failover outbound group protocol type (sing-box-extended).
	TypeFailover = "failover"
)

// sing-box endpoint type strings. These are the Type values sing-box uses inside its
// endpoint envelope (option.Endpoint.Type), distinct from the cheburbox inbound and
// outbound protocol types above. They are consumed by the config generator only.
const (
	// EndpointTypeWireGuard is the sing-box wireguard endpoint type. AmneziaWG rides
	// on the same endpoint type and is distinguished by a non-nil amnezia block.
	EndpointTypeWireGuard = "wireguard"
)

// Hysteria2 obfuscation and VLESS flow control feature strings.
const (
	// ObfsSalamander is the hysteria2 salamander obfuscation type.
	ObfsSalamander = "salamander"
	// FlowXTLSRPRXVision is the VLESS XTLS Vision flow control value.
	FlowXTLSRPRXVision = "xtls-rprx-vision"
)

// Failover dial strategy values for the failover outbound group.
const (
	// FailoverStrategySequential dials outbounds in declaration order, advancing
	// to the next only when the current one fails. This is the default.
	FailoverStrategySequential = "sequential"
	// FailoverStrategyCycle tries each outbound in turn on every dial, advancing
	// to the next on failure with an optional delay before retrying.
	FailoverStrategyCycle = "cycle"
)
