package generate

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"

	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	singjson "github.com/sagernet/sing/common/json"

	"github.com/Arsolitt/cheburbox/config"
	"github.com/Arsolitt/cheburbox/ruleset"
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

	ruleSetFiles, err := compileRuleSets(dir, &cfg)
	if err != nil {
		return GenerateResult{}, fmt.Errorf("compile rule-sets: %w", err)
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

	files := make([]FileOutput, 0, 1+len(certFiles)+len(ruleSetFiles))
	files = append(files, FileOutput{Path: "config.json", Content: configJSON})
	files = append(files, certFiles...)
	files = append(files, ruleSetFiles...)

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
			if uc, ok := findPersistedUser(persisted, in.Tag, user.Name); ok {
				creds.Users[user.Name] = UserCreds{
					UUID:     uc.UUID,
					Password: uc.Password,
					Flow:     uc.Flow,
				}
				continue
			}

			creds.Users[user.Name] = generateUserCreds(in.Type)
		}

		if !clean {
			for name, uc := range persisted.InboundUsers[in.Tag] {
				if _, declared := creds.Users[name]; !declared {
					creds.Users[name] = UserCreds{
						UUID:     uc.UUID,
						Password: uc.Password,
						Flow:     uc.Flow,
					}
				}
			}
		}

		resolveRealityKeys(in, persisted, &creds)
		resolveObfsPassword(in, persisted, &creds)
		resolveServerName(in, &creds)

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
	case inboundTypeVLESS:
		return UserCreds{UUID: GenerateUUID(), Flow: "xtls-rprx-vision"}
	case inboundTypeHysteria2:
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
	if in.Type != inboundTypeVLESS || in.TLS == nil || in.TLS.Reality == nil {
		return
	}

	if rk, ok := persisted.RealityKeys[in.Tag]; ok {
		publicKey := rk.PublicKey
		if publicKey == "" && rk.PrivateKey != "" {
			var deriveErr error
			publicKey, deriveErr = DerivePublicKey(rk.PrivateKey)
			if deriveErr != nil {
				return
			}
		}
		creds.Reality = &RealityKeys{
			PrivateKey: rk.PrivateKey,
			PublicKey:  publicKey,
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
	if in.Type != inboundTypeHysteria2 || in.Obfs == nil {
		return
	}

	if pw, ok := persisted.ObfsPasswords[in.Tag]; ok {
		creds.ObfsPassword = pw
		return
	}

	creds.ObfsPassword = GeneratePassword()
}

func resolveServerName(in config.Inbound, creds *InboundCredentials) {
	if in.TLS != nil {
		creds.ServerName = in.TLS.ServerName
	}
}

// resolveCertificates handles TLS certificate generation for hysteria2 inbounds.
// It reads existing certs, checks if they need regeneration, and generates new
// ones if needed.
func resolveCertificates(dir string, cfg config.Config, clean bool) ([]FileOutput, error) {
	var files []FileOutput

	for _, in := range cfg.Inbounds {
		if in.Type != inboundTypeHysteria2 || in.TLS == nil || in.TLS.ServerName == "" {
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

func compileRuleSets(dir string, cfg *config.Config) ([]FileOutput, error) {
	if cfg.Route == nil || len(cfg.Route.CustomRuleSets) == 0 {
		return nil, nil
	}

	sources, err := ruleset.FindSourceFiles(dir, cfg.Route.CustomRuleSets)
	if err != nil {
		return nil, fmt.Errorf("discover rule-set sources: %w", err)
	}

	if len(sources) == 0 {
		return nil, nil
	}

	ruleSetDir := filepath.Join(dir, "rule-set")
	if err := os.MkdirAll(ruleSetDir, 0o750); err != nil {
		return nil, fmt.Errorf("create rule-set directory: %w", err)
	}

	files := make([]FileOutput, 0, len(sources))
	for _, src := range sources {
		content, readErr := os.ReadFile(src.Path)
		if readErr != nil {
			return nil, fmt.Errorf("read rule-set source %s: %w", src.Name, readErr)
		}

		outputPath := filepath.Join(ruleSetDir, src.Name+".srs")
		if err := ruleset.Compile(content, outputPath); err != nil {
			return nil, fmt.Errorf("compile rule-set %s: %w", src.Name, err)
		}

		compiledContent, readErr := os.ReadFile(outputPath)
		if readErr != nil {
			return nil, fmt.Errorf("read compiled rule-set %s: %w", src.Name, readErr)
		}

		relPath := filepath.Join("rule-set", src.Name+".srs")
		files = append(files, FileOutput{Path: relPath, Content: compiledContent})
	}

	return files, nil
}

// GenerateAll discovers all servers in the project, builds a dependency graph,
// topologically sorts them, and generates configs in order with shared state
// for cross-server credential resolution. Uses two-pass generation to handle
// cross-server user provisioning.
//
//nolint:revive // "generate.Generate" stutter is intentional for API clarity.
func GenerateAll(projectRoot string, jpath string, genCfg GenerateConfig) ([]GenerateResult, error) {
	servers, err := config.Discover(projectRoot)
	if err != nil {
		return nil, fmt.Errorf("discover servers: %w", err)
	}

	if len(servers) == 0 {
		return nil, nil
	}

	configs, err := loadAllConfigs(servers, projectRoot, jpath)
	if err != nil {
		return nil, err
	}

	graph, err := BuildGraph(configs)
	if err != nil {
		return nil, fmt.Errorf("build dependency graph: %w", err)
	}

	order, err := graph.TopologicalSort()
	if err != nil {
		return nil, fmt.Errorf("topological sort: %w", err)
	}

	return generateWithDAG(projectRoot, configs, order, genCfg)
}

// GenerateServers generates configs for the specified server and its transitive
// dependencies.
//
//nolint:revive // "generate.Generate" stutter is intentional for API clarity.
func GenerateServers(
	projectRoot string,
	jpath string,
	serverName string,
	genCfg GenerateConfig,
) ([]GenerateResult, error) {
	servers, err := config.Discover(projectRoot)
	if err != nil {
		return nil, fmt.Errorf("discover servers: %w", err)
	}

	configs, err := loadAllConfigs(servers, projectRoot, jpath)
	if err != nil {
		return nil, err
	}

	graph, err := BuildGraph(configs)
	if err != nil {
		return nil, fmt.Errorf("build dependency graph: %w", err)
	}

	deps, err := graph.TransitiveDependencies(serverName)
	if err != nil {
		return nil, fmt.Errorf("resolve dependencies for %s: %w", serverName, err)
	}

	subConfigs := make(map[string]config.Config, len(deps))
	for _, dep := range deps {
		subConfigs[dep] = configs[dep]
	}

	subGraph, err := BuildGraph(subConfigs)
	if err != nil {
		return nil, fmt.Errorf("build sub-graph: %w", err)
	}

	order, err := subGraph.TopologicalSort()
	if err != nil {
		return nil, fmt.Errorf("topological sort: %w", err)
	}

	return generateWithDAG(projectRoot, configs, order, genCfg)
}

func generateWithDAG(
	projectRoot string,
	configs map[string]config.Config,
	order []string,
	genCfg GenerateConfig,
) ([]GenerateResult, error) {
	state := NewServerState()
	resultMap := make(map[string]GenerateResult, len(order))

	for _, name := range order {
		result, dirty, genErr := generateServerWithState(
			filepath.Join(projectRoot, name),
			name,
			configs[name],
			genCfg,
			state,
		)
		if genErr != nil {
			return nil, fmt.Errorf("server %s: %w", name, genErr)
		}
		resultMap[name] = result

		for target := range dirty {
			if _, exists := resultMap[target]; exists {
				result, regenErr := regenerateServer(
					filepath.Join(projectRoot, target),
					target,
					configs[target],
					genCfg,
					state,
				)
				if regenErr != nil {
					return nil, fmt.Errorf("regenerate server %s: %w", target, regenErr)
				}
				resultMap[target] = result
			}
		}
	}

	results := make([]GenerateResult, 0, len(order))
	for _, name := range order {
		results = append(results, resultMap[name])
	}

	return results, nil
}

func loadAllConfigs(
	servers []string,
	projectRoot string,
	jpath string,
) (map[string]config.Config, error) {
	configs := make(map[string]config.Config, len(servers))

	for _, name := range servers {
		dir := filepath.Join(projectRoot, name)
		cfg, err := config.LoadServerWithJsonnet(dir, jpath)
		if err != nil {
			return nil, fmt.Errorf("load config for %s: %w", name, err)
		}
		if err := config.Validate(cfg); err != nil {
			return nil, fmt.Errorf("validate config for %s: %w", name, err)
		}
		configs[name] = cfg
	}

	return configs, nil
}

func generateServerWithState(
	dir string,
	serverName string,
	cfg config.Config,
	genCfg GenerateConfig,
	state *ServerState,
) (GenerateResult, map[string]bool, error) {
	persisted, err := config.LoadPersistedCredentials(filepath.Join(dir, "config.json"))
	if err != nil {
		return GenerateResult{}, nil, fmt.Errorf("load persisted credentials: %w", err)
	}

	credsMap := resolveCredentials(cfg, persisted, genCfg.Clean)

	for _, in := range cfg.Inbounds {
		state.StoreInboundType(serverName, in.Tag, in.Type)
		if in.ListenPort > 0 && in.ListenPort <= math.MaxUint16 {
			state.StoreListenPort(serverName, in.Tag, uint16(in.ListenPort))
		}
		mergeCredentialsIntoState(state, serverName, in.Tag, credsMap[in.Tag])
	}

	certFiles, err := resolveCertificatesWithState(dir, cfg, genCfg.Clean, state, serverName)
	if err != nil {
		return GenerateResult{}, nil, fmt.Errorf("resolve certificates: %w", err)
	}

	state.StoreEndpoint(serverName, cfg.Endpoint)

	dirty := provisionCrossServerUsers(cfg, state, serverName)

	mergeStateUsersIntoCredsMap(serverName, credsMap, state)

	ruleSetFiles, err := compileRuleSets(dir, &cfg)
	if err != nil {
		return GenerateResult{}, nil, fmt.Errorf("compile rule-sets: %w", err)
	}

	dnsOpts, err := ConvertDNS(cfg.DNS)
	if err != nil {
		return GenerateResult{}, nil, fmt.Errorf("convert dns: %w", err)
	}

	routeOpts, err := ConvertRoute(cfg.Route)
	if err != nil {
		return GenerateResult{}, nil, fmt.Errorf("convert route: %w", err)
	}

	inbounds, err := buildInbounds(cfg.Inbounds, credsMap)
	if err != nil {
		return GenerateResult{}, nil, fmt.Errorf("build inbounds: %w", err)
	}

	outbounds, err := buildOutboundsWithState(cfg.Outbounds, state, serverName)
	if err != nil {
		return GenerateResult{}, nil, fmt.Errorf("build outbounds: %w", err)
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
			return GenerateResult{}, nil, fmt.Errorf("unmarshal log: %w", logErr)
		}
		opts.Log = logOpts
	}

	if cfg.Route == nil && opts.Route != nil {
		opts.Route.AutoDetectInterface = true
	}

	addBoilerplate(&opts)

	configJSON, err := marshalOptions(&opts)
	if err != nil {
		return GenerateResult{}, nil, fmt.Errorf("marshal config: %w", err)
	}

	files := make([]FileOutput, 0, 1+len(certFiles)+len(ruleSetFiles))
	files = append(files, FileOutput{Path: "config.json", Content: configJSON})
	files = append(files, certFiles...)
	files = append(files, ruleSetFiles...)

	return GenerateResult{
		Server: serverName,
		Files:  files,
	}, dirty, nil
}

func regenerateServer(
	dir string,
	serverName string,
	cfg config.Config,
	genCfg GenerateConfig,
	state *ServerState,
) (GenerateResult, error) {
	persisted, err := config.LoadPersistedCredentials(filepath.Join(dir, "config.json"))
	if err != nil {
		return GenerateResult{}, fmt.Errorf("load persisted credentials: %w", err)
	}

	credsMap := resolveCredentials(cfg, persisted, genCfg.Clean)

	for _, in := range cfg.Inbounds {
		state.StoreInboundType(serverName, in.Tag, in.Type)
		if in.ListenPort > 0 && in.ListenPort <= math.MaxUint16 {
			state.StoreListenPort(serverName, in.Tag, uint16(in.ListenPort))
		}
		mergeCredentialsIntoState(state, serverName, in.Tag, credsMap[in.Tag])
	}

	mergeStateUsersIntoCredsMap(serverName, credsMap, state)

	ruleSetFiles, err := compileRuleSets(dir, &cfg)
	if err != nil {
		return GenerateResult{}, fmt.Errorf("compile rule-sets: %w", err)
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

	outbounds, err := buildOutboundsWithState(cfg.Outbounds, state, serverName)
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

	certFiles, err := resolveCertificatesWithState(dir, cfg, genCfg.Clean, state, serverName)
	if err != nil {
		return GenerateResult{}, fmt.Errorf("resolve certificates: %w", err)
	}

	files := make([]FileOutput, 0, 1+len(certFiles)+len(ruleSetFiles))
	files = append(files, FileOutput{Path: "config.json", Content: configJSON})
	files = append(files, certFiles...)
	files = append(files, ruleSetFiles...)

	return GenerateResult{
		Server: serverName,
		Files:  files,
	}, nil
}

func provisionCrossServerUsers(cfg config.Config, state *ServerState, serverName string) map[string]bool {
	dirty := make(map[string]bool)

	for _, out := range cfg.Outbounds {
		if out.Server == "" {
			continue
		}
		if out.Type != inboundTypeVLESS && out.Type != inboundTypeHysteria2 {
			continue
		}

		user := out.User
		if user == "" {
			user = serverName
		}

		creds, ok := state.GetInboundCredentials(out.Server, out.Inbound)
		if !ok {
			continue
		}

		if _, exists := creds.Users[user]; exists {
			continue
		}

		if err := state.EnsureUser(out.Server, out.Inbound, user); err != nil {
			continue
		}

		dirty[out.Server] = true
	}

	return dirty
}

func mergeCredentialsIntoState(state *ServerState, server string, tag string, creds InboundCredentials) {
	existing, ok := state.GetInboundCredentials(server, tag)
	if !ok {
		state.StoreInboundCredentials(server, tag, creds)
		return
	}

	for user, userCreds := range creds.Users {
		if _, exists := existing.Users[user]; !exists {
			existing.Users[user] = userCreds
		}
	}

	if existing.Reality == nil && creds.Reality != nil {
		existing.Reality = creds.Reality
	}
	if existing.ObfsPassword == "" && creds.ObfsPassword != "" {
		existing.ObfsPassword = creds.ObfsPassword
	}
	if existing.ServerName == "" && creds.ServerName != "" {
		existing.ServerName = creds.ServerName
	}

	state.StoreInboundCredentials(server, tag, existing)
}

func mergeStateUsersIntoCredsMap(serverName string, credsMap map[string]InboundCredentials, state *ServerState) {
	for tag := range credsMap {
		stateCreds, ok := state.GetInboundCredentials(serverName, tag)
		if !ok {
			continue
		}

		for user, userCreds := range stateCreds.Users {
			if _, exists := credsMap[tag].Users[user]; !exists {
				credsMap[tag].Users[user] = userCreds
			}
		}
	}
}

func buildOutboundsWithState(
	outbounds []config.Outbound,
	state *ServerState,
	serverName string,
) ([]option.Outbound, error) {
	result := make([]option.Outbound, 0, len(outbounds))
	for _, out := range outbounds {
		ob, err := BuildOutboundWithState(out, state, WithDefaultUser(serverName))
		if err != nil {
			return nil, fmt.Errorf("outbound %q: %w", out.Tag, err)
		}
		result = append(result, ob)
	}
	return result, nil
}

func resolveCertificatesWithState(
	dir string,
	cfg config.Config,
	clean bool,
	state *ServerState,
	serverName string,
) ([]FileOutput, error) {
	files, err := resolveCertificates(dir, cfg, clean)
	if err != nil {
		return nil, err
	}

	for _, in := range cfg.Inbounds {
		if in.Type != inboundTypeHysteria2 || in.TLS == nil || in.TLS.ServerName == "" {
			continue
		}

		certRelPath := filepath.Join("certs", in.TLS.ServerName+".crt")
		certFile := findFileInList(files, certRelPath)
		if certFile == nil {
			continue
		}

		pin, pinErr := computePinSHA256(certFile.Content)
		if pinErr != nil {
			return nil, fmt.Errorf("compute pin-sha256 for %q: %w", in.TLS.ServerName, pinErr)
		}

		state.StorePinSHA256(serverName, in.Tag, pin)
	}

	return files, nil
}

func findFileInList(files []FileOutput, path string) *FileOutput {
	for i := range files {
		if files[i].Path == path {
			return &files[i]
		}
	}
	return nil
}
