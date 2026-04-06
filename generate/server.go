package generate

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"path/filepath"

	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	singjson "github.com/sagernet/sing/common/json"

	"github.com/Arsolitt/cheburbox/config"
)

// GenerateConfig controls server generation behavior.
//
//nolint:revive // "generate.Generate" stutter is intentional for API clarity.
type GenerateConfig struct {
	Clean bool
}

// GenerateResult holds the generated server name and output files.
//
//nolint:revive // "generate.Generate" stutter is intentional for API clarity.
type GenerateResult struct {
	Server string
	Files  []FileOutput
}

// FileOutput represents a generated file with its relative path and content.
type FileOutput struct {
	Path    string
	Content []byte
}

// GenerateServer generates a complete sing-box configuration for a server.
// It resolves credentials, builds all options, adds boilerplate settings,
// and marshals the result to JSON.
//
//nolint:revive // "generate.Generate" stutter is intentional for API clarity.
func GenerateServer(dir string, cfg config.Config, genCfg GenerateConfig) (GenerateResult, error) {
	configPath := filepath.Join(dir, "config.json")

	persisted, err := config.LoadPersistedCredentials(configPath)
	if err != nil {
		return GenerateResult{}, fmt.Errorf("load persisted credentials: %w", err)
	}

	credsMap := resolveCredentials(cfg, persisted, genCfg.Clean)

	certFiles, err := resolveCertificates(dir, cfg, genCfg.Clean)
	if err != nil {
		return GenerateResult{}, fmt.Errorf("resolve certificates: %w", err)
	}

	dnsOpts, err := ConvertDNS(cfg.DNS)
	if err != nil {
		return GenerateResult{}, fmt.Errorf("convert dns: %w", err)
	}

	routeOpts, err := ConvertRoute(cfg.Route)
	if err != nil {
		return GenerateResult{}, fmt.Errorf("convert route: %w", err)
	}

	inbounds, err := buildInbounds(cfg.Inbounds, credsMap)
	if err != nil {
		return GenerateResult{}, fmt.Errorf("build inbounds: %w", err)
	}

	outbounds, err := buildOutbounds(cfg.Outbounds)
	if err != nil {
		return GenerateResult{}, fmt.Errorf("build outbounds: %w", err)
	}

	opts := option.Options{
		DNS:       dnsOpts,
		Route:     routeOpts,
		Inbounds:  inbounds,
		Outbounds: outbounds,
	}

	if len(cfg.Log) > 0 {
		logOpts, logErr := unmarshalLog(cfg.Log)
		if logErr != nil {
			return GenerateResult{}, fmt.Errorf("unmarshal log: %w", logErr)
		}
		opts.Log = logOpts
	}

	if cfg.Route == nil && opts.Route != nil {
		opts.Route.AutoDetectInterface = true
	}

	addBoilerplate(&opts)

	configJSON, err := marshalOptions(&opts)
	if err != nil {
		return GenerateResult{}, fmt.Errorf("marshal config: %w", err)
	}

	files := make([]FileOutput, 0, 1+len(certFiles))
	files = append(files, FileOutput{Path: "config.json", Content: configJSON})
	files = append(files, certFiles...)

	return GenerateResult{
		Server: filepath.Base(dir),
		Files:  files,
	}, nil
}

// resolveCredentials merges persisted credentials with newly generated ones
// for all inbounds in the configuration.
// When clean is false, extra persisted users not declared in the config are preserved.
func resolveCredentials(
	cfg config.Config,
	persisted config.PersistedCredentials,
	clean bool,
) map[string]InboundCredentials {
	credsMap := make(map[string]InboundCredentials, len(cfg.Inbounds))

	for _, in := range cfg.Inbounds {
		creds := InboundCredentials{
			Users: make(map[string]UserCreds, len(in.Users)),
		}

		for _, user := range in.Users {
			if uc, ok := findPersistedUser(persisted, in.Tag, user); ok {
				creds.Users[user] = UserCreds{
					UUID:     uc.UUID,
					Password: uc.Password,
				}
				continue
			}

			creds.Users[user] = generateUserCreds(in.Type)
		}

		if !clean {
			for name, uc := range persisted.InboundUsers[in.Tag] {
				if _, declared := creds.Users[name]; !declared {
					creds.Users[name] = UserCreds{
						UUID:     uc.UUID,
						Password: uc.Password,
					}
				}
			}
		}

		resolveRealityKeys(in, persisted, &creds)
		resolveObfsPassword(in, persisted, &creds)

		credsMap[in.Tag] = creds
	}

	return credsMap
}

func findPersistedUser(
	persisted config.PersistedCredentials,
	tag string,
	user string,
) (config.UserCredentials, bool) {
	tagUsers, ok := persisted.InboundUsers[tag]
	if !ok {
		return config.UserCredentials{}, false
	}
	uc, ok := tagUsers[user]
	return uc, ok
}

func generateUserCreds(inboundType string) UserCreds {
	switch inboundType {
	case "vless":
		return UserCreds{UUID: GenerateUUID()}
	case "hysteria2":
		return UserCreds{Password: GeneratePassword()}
	default:
		return UserCreds{}
	}
}

func resolveRealityKeys(
	in config.Inbound,
	persisted config.PersistedCredentials,
	creds *InboundCredentials,
) {
	if in.Type != "vless" || in.TLS == nil || in.TLS.Reality == nil {
		return
	}

	if rk, ok := persisted.RealityKeys[in.Tag]; ok {
		creds.Reality = &RealityKeys{
			PrivateKey: rk.PrivateKey,
			PublicKey:  rk.PublicKey,
			ShortID:    rk.ShortID,
		}
		return
	}

	priv, pub := GenerateX25519KeyPair()
	shortID := GenerateShortID()
	creds.Reality = &RealityKeys{
		PrivateKey: priv,
		PublicKey:  pub,
		ShortID:    []string{shortID},
	}
}

func resolveObfsPassword(
	in config.Inbound,
	persisted config.PersistedCredentials,
	creds *InboundCredentials,
) {
	if in.Type != "hysteria2" || in.Obfs == nil {
		return
	}

	if pw, ok := persisted.ObfsPasswords[in.Tag]; ok {
		creds.ObfsPassword = pw
		return
	}

	creds.ObfsPassword = GeneratePassword()
}

// resolveCertificates handles TLS certificate generation for hysteria2 inbounds.
// It reads existing certs, checks if they need regeneration, and generates new
// ones if needed.
func resolveCertificates(dir string, cfg config.Config, clean bool) ([]FileOutput, error) {
	var files []FileOutput

	for _, in := range cfg.Inbounds {
		if in.Type != "hysteria2" || in.TLS == nil || in.TLS.ServerName == "" {
			continue
		}

		serverName := in.TLS.ServerName
		certRelPath := filepath.Join("certs", serverName+".crt")
		keyRelPath := filepath.Join("certs", serverName+".key")
		certAbsPath := filepath.Join(dir, certRelPath)
		keyAbsPath := filepath.Join(dir, keyRelPath)

		certPEM, keyPEM, err := ReadCertFiles(certAbsPath, keyAbsPath)
		if err != nil {
			return nil, fmt.Errorf("read cert files for %q: %w", serverName, err)
		}

		needsRegen := clean
		if !needsRegen && certPEM != nil {
			cert, parseErr := parseCertPEM(certPEM)
			if parseErr != nil || CertNeedsRegeneration(cert, serverName) {
				needsRegen = true
			}
		}

		if certPEM == nil || keyPEM == nil || needsRegen {
			certPEM, keyPEM = GenerateSelfSignedCertPEM(serverName)
		}

		files = append(files,
			FileOutput{Path: certRelPath, Content: certPEM},
			FileOutput{Path: keyRelPath, Content: keyPEM},
		)
	}

	return files, nil
}

// addBoilerplate sets default experimental options on the sing-box configuration.
func addBoilerplate(opts *option.Options) {
	opts.Experimental = &option.ExperimentalOptions{
		CacheFile: &option.CacheFileOptions{Enabled: true},
	}
}

func parseCertPEM(certPEM []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}
	return x509.ParseCertificate(block.Bytes)
}

func unmarshalLog(raw json.RawMessage) (*option.LogOptions, error) {
	ctx := include.Context(context.Background())
	var logOpts option.LogOptions
	if err := singjson.UnmarshalContext(ctx, raw, &logOpts); err != nil {
		return nil, fmt.Errorf("parse log options: %w", err)
	}
	return &logOpts, nil
}

func buildInbounds(inbounds []config.Inbound, credsMap map[string]InboundCredentials) ([]option.Inbound, error) {
	result := make([]option.Inbound, 0, len(inbounds))
	for _, in := range inbounds {
		creds := credsMap[in.Tag]
		inbound, err := BuildInbound(in, creds)
		if err != nil {
			return nil, fmt.Errorf("inbound %q: %w", in.Tag, err)
		}
		result = append(result, inbound)
	}
	return result, nil
}

func buildOutbounds(outbounds []config.Outbound) ([]option.Outbound, error) {
	result := make([]option.Outbound, 0, len(outbounds))
	for _, out := range outbounds {
		outbound, err := BuildOutbound(out)
		if err != nil {
			return nil, fmt.Errorf("outbound %q: %w", out.Tag, err)
		}
		result = append(result, outbound)
	}
	return result, nil
}

func marshalOptions(opts *option.Options) ([]byte, error) {
	ctx := include.Context(context.Background())
	data, err := singjson.MarshalContext(ctx, opts)
	if err != nil {
		return nil, fmt.Errorf("marshal: %w", err)
	}

	var buf bytes.Buffer
	if err := json.Indent(&buf, data, "", "  "); err != nil {
		return nil, fmt.Errorf("indent: %w", err)
	}
	buf.WriteByte('\n')

	return buf.Bytes(), nil
}
