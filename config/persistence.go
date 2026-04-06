package config

import (
	"context"
	"fmt"
	"os"

	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	singjson "github.com/sagernet/sing/common/json"
)

// PersistedCredentials holds all credentials extracted from a sing-box config.json.
type PersistedCredentials struct {
	InboundUsers  map[string]map[string]UserCredentials
	RealityKeys   map[string]RealityKeyPair
	ObfsPasswords map[string]string
}

// UserCredentials holds UUID or password for a single inbound user.
type UserCredentials struct {
	UUID     string
	Password string
}

// RealityKeyPair holds Reality TLS key material for an inbound.
type RealityKeyPair struct {
	PrivateKey string
	PublicKey  string
	ShortID    []string
}

// EmptyPersistedCredentials returns a zero-value PersistedCredentials with
// initialized maps.
func EmptyPersistedCredentials() PersistedCredentials {
	return PersistedCredentials{
		InboundUsers:  make(map[string]map[string]UserCredentials),
		RealityKeys:   make(map[string]RealityKeyPair),
		ObfsPasswords: make(map[string]string),
	}
}

// LoadPersistedCredentials reads a sing-box config.json from configPath,
// parses it using sing-box option structs, and extracts all credentials.
// Returns empty credentials if the file does not exist.
func LoadPersistedCredentials(configPath string) (PersistedCredentials, error) {
	data, err := os.ReadFile(configPath)
	if os.IsNotExist(err) {
		return EmptyPersistedCredentials(), nil
	}
	if err != nil {
		return PersistedCredentials{}, fmt.Errorf("read %s: %w", configPath, err)
	}

	ctx := include.Context(context.Background())
	var opts option.Options
	if err := singjson.UnmarshalContext(ctx, data, &opts); err != nil {
		return PersistedCredentials{}, fmt.Errorf("parse %s: %w", configPath, err)
	}

	return ExtractCredentials(&opts), nil
}

// ExtractCredentials extracts all credentials from a parsed sing-box Options
// struct, including VLESS users with UUIDs, Hysteria2 users with passwords,
// Reality key pairs, and obfuscation passwords.
func ExtractCredentials(opts *option.Options) PersistedCredentials {
	creds := EmptyPersistedCredentials()

	for _, inbound := range opts.Inbounds {
		switch o := inbound.Options.(type) {
		case *option.VLESSInboundOptions:
			extractVLESSCredentials(inbound.Tag, o, &creds)
		case *option.Hysteria2InboundOptions:
			extractHysteria2Credentials(inbound.Tag, o, &creds)
		}
	}

	return creds
}

func extractVLESSCredentials(tag string, opts *option.VLESSInboundOptions, creds *PersistedCredentials) {
	users := make(map[string]UserCredentials, len(opts.Users))
	for _, u := range opts.Users {
		users[u.Name] = UserCredentials{UUID: u.UUID}
	}
	creds.InboundUsers[tag] = users

	if opts.TLS != nil && opts.TLS.Reality != nil && opts.TLS.Reality.Enabled {
		reality := opts.TLS.Reality
		creds.RealityKeys[tag] = RealityKeyPair{
			PrivateKey: reality.PrivateKey,
			ShortID:    []string(reality.ShortID),
		}
	}
}

func extractHysteria2Credentials(tag string, opts *option.Hysteria2InboundOptions, creds *PersistedCredentials) {
	users := make(map[string]UserCredentials, len(opts.Users))
	for _, u := range opts.Users {
		users[u.Name] = UserCredentials{Password: u.Password}
	}
	creds.InboundUsers[tag] = users

	if opts.Obfs != nil && opts.Obfs.Password != "" {
		creds.ObfsPasswords[tag] = opts.Obfs.Password
	}
}
