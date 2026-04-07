package generate

import (
	"fmt"
)

// ServerState holds per-server state for credentials, pin-SHA256, endpoints, inbound types, and listen ports.
type ServerState struct {
	credentials map[string]map[string]InboundCredentials
	pinSHA256   map[string]map[string]string
	endpoints   map[string]string
	inboundType map[string]map[string]string
	listenPort  map[string]map[string]uint16
}

// NewServerState creates an empty ServerState ready for use.
func NewServerState() *ServerState {
	return &ServerState{
		credentials: make(map[string]map[string]InboundCredentials),
		pinSHA256:   make(map[string]map[string]string),
		endpoints:   make(map[string]string),
		inboundType: make(map[string]map[string]string),
		listenPort:  make(map[string]map[string]uint16),
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

	newCreds := generateUserCreds(inboundType)
	creds.Users[userName] = newCreds
	s.StoreInboundCredentials(server, tag, creds)

	return nil
}
