package generate

import (
	"fmt"
	"net/netip"

	"github.com/sagernet/sing-box/option"
)

// ServerState holds per-server state for credentials, pin-SHA256, endpoints,
// inbound types, listen ports, and AmneziaWG server/peer registries.
type ServerState struct {
	credentials       map[string]map[string]InboundCredentials
	pinSHA256         map[string]map[string]string
	endpoints         map[string]string
	inboundType       map[string]map[string]string
	listenPort        map[string]map[string]uint16
	amneziaWGServer   map[string]map[string]AmneziaWGServerInfo
	amneziaWGPeers    map[string]map[string]map[string]AmneziaWGPeerCreds
	amneziaWGMaterial map[string]map[string]amneziaWGServerMaterial
}

func NewServerState() *ServerState {
	return &ServerState{
		credentials:       make(map[string]map[string]InboundCredentials),
		pinSHA256:         make(map[string]map[string]string),
		endpoints:         make(map[string]string),
		inboundType:       make(map[string]map[string]string),
		listenPort:        make(map[string]map[string]uint16),
		amneziaWGServer:   make(map[string]map[string]AmneziaWGServerInfo),
		amneziaWGPeers:    make(map[string]map[string]map[string]AmneziaWGPeerCreds),
		amneziaWGMaterial: make(map[string]map[string]amneziaWGServerMaterial),
	}
}

// StoreInboundCredentials saves credentials for a server's inbound.
func (s *ServerState) StoreInboundCredentials(server string, tag string, creds InboundCredentials) {
	if s.credentials[server] == nil {
		s.credentials[server] = make(map[string]InboundCredentials)
	}
	s.credentials[server][tag] = creds
}

// GetInboundCredentials retrieves credentials for a server's inbound.
func (s *ServerState) GetInboundCredentials(server string, tag string) (InboundCredentials, bool) {
	tags, ok := s.credentials[server]
	if !ok {
		return InboundCredentials{}, false
	}
	creds, ok := tags[tag]
	return creds, ok
}

// StorePinSHA256 saves the TLS pin-SHA256 fingerprint for a server's inbound.
func (s *ServerState) StorePinSHA256(server string, tag string, pin string) {
	if s.pinSHA256[server] == nil {
		s.pinSHA256[server] = make(map[string]string)
	}
	s.pinSHA256[server][tag] = pin
}

// GetPinSHA256 retrieves the TLS pin-SHA256 fingerprint for a server's inbound.
func (s *ServerState) GetPinSHA256(server string, tag string) (string, bool) {
	tags, ok := s.pinSHA256[server]
	if !ok {
		return "", false
	}
	pin, ok := tags[tag]
	return pin, ok
}

// StoreEndpoint saves the public endpoint address for a server.
func (s *ServerState) StoreEndpoint(server string, endpoint string) {
	s.endpoints[server] = endpoint
}

// GetEndpoint retrieves the public endpoint address for a server.
func (s *ServerState) GetEndpoint(server string) (string, bool) {
	ep, ok := s.endpoints[server]
	return ep, ok
}

// StoreInboundType saves the inbound protocol type for a server's inbound.
func (s *ServerState) StoreInboundType(server string, tag string, inboundType string) {
	if s.inboundType[server] == nil {
		s.inboundType[server] = make(map[string]string)
	}
	s.inboundType[server][tag] = inboundType
}

// GetInboundType retrieves the inbound protocol type for a server's inbound.
func (s *ServerState) GetInboundType(server string, tag string) (string, bool) {
	tags, ok := s.inboundType[server]
	if !ok {
		return "", false
	}
	typ, ok := tags[tag]
	return typ, ok
}

// StoreListenPort saves the listen port for a server's inbound.
func (s *ServerState) StoreListenPort(server string, tag string, port uint16) {
	if s.listenPort[server] == nil {
		s.listenPort[server] = make(map[string]uint16)
	}
	s.listenPort[server][tag] = port
}

// GetListenPort retrieves the listen port for a server's inbound.
func (s *ServerState) GetListenPort(server string, tag string) (uint16, bool) {
	tags, ok := s.listenPort[server]
	if !ok {
		return 0, false
	}
	port, ok := tags[tag]
	return port, ok
}

// EnsureUser adds a user with generated credentials to an existing inbound.
// If the user already exists, their credentials are preserved.
func (s *ServerState) EnsureUser(server string, tag string, userName string) error {
	creds, ok := s.GetInboundCredentials(server, tag)
	if !ok {
		return fmt.Errorf("server %q has no inbound %q", server, tag)
	}

	if _, exists := creds.Users[userName]; exists {
		return nil
	}

	inboundType, ok := s.GetInboundType(server, tag)
	if !ok {
		return fmt.Errorf("server %q inbound %q has no known type", server, tag)
	}

	newCreds, err := generateUserCreds(inboundType)
	if err != nil {
		return fmt.Errorf("generate credentials for user %q: %w", userName, err)
	}
	creds.Users[userName] = newCreds
	s.StoreInboundCredentials(server, tag, creds)

	return nil
}

// AmneziaWGServerInfo holds the resolved server-side state for an AmneziaWG
// inbound. Client endpoints look it up to inherit the server's public key,
// public UDP endpoint, transport protocol, and the shared amnezia obfuscation
// parameters that every peer must match.
type AmneziaWGServerInfo struct {
	Subnet        netip.Prefix
	PublicKey     string
	EndpointAddr  string
	Protocol      string
	SharedAmnezia option.WireGuardAmnezia
	MTU           uint32
	ListenPort    uint16
}

// AmneziaWGPeerCreds holds a single AmneziaWG peer's credentials. PublicKey and
// PresharedKey are what the SERVER installs in its peer list; PrivateKey is the
// peer's own key and is only meaningful on the client side. AllowedIPs is the
// tunnel address the server routes to this peer (typically a /32).
type AmneziaWGPeerCreds struct {
	PrivateKey   string
	PublicKey    string
	PresharedKey string
	AllowedIPs   []netip.Prefix
}

// RegisterAmneziaWGServer records the server-side state for an AmneziaWG
// inbound so client endpoints on other servers can look it up.
func (s *ServerState) RegisterAmneziaWGServer(server string, tag string, info AmneziaWGServerInfo) {
	if s.amneziaWGServer[server] == nil {
		s.amneziaWGServer[server] = make(map[string]AmneziaWGServerInfo)
	}
	s.amneziaWGServer[server][tag] = info
}

// AmneziaWGServer looks up the server-side state for an AmneziaWG inbound.
func (s *ServerState) AmneziaWGServer(server string, tag string) (AmneziaWGServerInfo, bool) {
	tags, ok := s.amneziaWGServer[server]
	if !ok {
		return AmneziaWGServerInfo{}, false
	}
	info, ok := tags[tag]
	return info, ok
}

// StoreAmneziaWGPeer saves credentials for a single AmneziaWG peer provisioned
// against a server's inbound, keyed by peer (user) name.
func (s *ServerState) StoreAmneziaWGPeer(server string, tag string, user string, creds AmneziaWGPeerCreds) {
	if s.amneziaWGPeers[server] == nil {
		s.amneziaWGPeers[server] = make(map[string]map[string]AmneziaWGPeerCreds)
	}
	if s.amneziaWGPeers[server][tag] == nil {
		s.amneziaWGPeers[server][tag] = make(map[string]AmneziaWGPeerCreds)
	}
	s.amneziaWGPeers[server][tag][user] = creds
}

// AmneziaWGPeer looks up a single AmneziaWG peer by name.
func (s *ServerState) AmneziaWGPeer(server string, tag string, user string) (AmneziaWGPeerCreds, bool) {
	tags, ok := s.amneziaWGPeers[server]
	if !ok {
		return AmneziaWGPeerCreds{}, false
	}
	users, ok := tags[tag]
	if !ok {
		return AmneziaWGPeerCreds{}, false
	}
	creds, ok := users[user]
	return creds, ok
}

// AmneziaWGPeers returns all peers provisioned against a server's inbound.
// The server endpoint builder uses this to assemble its peer list.
func (s *ServerState) AmneziaWGPeers(server string, tag string) map[string]AmneziaWGPeerCreds {
	tags, ok := s.amneziaWGPeers[server]
	if !ok {
		return nil
	}
	return tags[tag]
}

// EnsureAmneziaWGPeer provisions a peer for (server, tag, user). If the peer
// already exists in the registry, its existing credentials are returned
// unchanged (alreadyExisted = true). Otherwise the supplied creds are stored
// and returned (alreadyExisted = false). The caller owns key generation and
// supplies the public/preshared keys; this keeps the peer's public key on the
// server consistent with the client's private key across generation runs.
func (s *ServerState) EnsureAmneziaWGPeer(
	server string,
	tag string,
	user string,
	creds AmneziaWGPeerCreds,
) (AmneziaWGPeerCreds, bool) {
	if existing, ok := s.AmneziaWGPeer(server, tag, user); ok {
		return existing, true
	}
	s.StoreAmneziaWGPeer(server, tag, user, creds)
	return creds, false
}

// amneziaWGServerMaterial caches the resolved server-side private key and
// shared amnezia block for an AmneziaWG inbound so that a regeneration pass
// (triggered by a cross-server client provisioning a new peer) reuses the exact
// same key material as the first pass. Without this, the server would
// regenerate fresh keys whenever a client dirtied it, desynchronising the
// client's already-built peer (which captured the first pass's public key).
type amneziaWGServerMaterial struct {
	PrivateKey string
	Amnezia    option.WireGuardAmnezia
}

// storeAmneziaWGMaterial caches the resolved server key material.
func (s *ServerState) storeAmneziaWGMaterial(server string, tag string, m amneziaWGServerMaterial) {
	if s.amneziaWGMaterial[server] == nil {
		s.amneziaWGMaterial[server] = make(map[string]amneziaWGServerMaterial)
	}
	s.amneziaWGMaterial[server][tag] = m
}

// lookupAmneziaWGMaterial returns cached server key material, if any.
func (s *ServerState) lookupAmneziaWGMaterial(server string, tag string) (amneziaWGServerMaterial, bool) {
	tags, ok := s.amneziaWGMaterial[server]
	if !ok {
		return amneziaWGServerMaterial{}, false
	}
	m, ok := tags[tag]
	return m, ok
}
