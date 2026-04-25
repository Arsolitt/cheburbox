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
	FullReset bool
	Orphan    bool
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
//
//nolint:revive // "generate.Generate" stutter is intentional for API clarity.
func GenerateServer(dir string, cfg config.Config, genCfg GenerateConfig) (GenerateResult, error) {
	state := NewServerState()
	result, _, err := generateServerWithState(dir, filepath.Base(dir), cfg, genCfg, state, nil)
	return result, err
}

// resolveCredentials merges persisted credentials with newly generated ones
// for all inbounds in the configuration.
// When FullReset is set, persisted credentials are discarded entirely.
// When Orphan is set, only cross-server referenced users are preserved.
// By default, all extra persisted users are preserved.
func resolveCredentials(
	cfg config.Config,
	persisted config.PersistedCredentials,
	genCfg GenerateConfig,
	crossServerUsers map[string]map[string]bool,
) (map[string]InboundCredentials, error) {
	if genCfg.FullReset {
		persisted = config.EmptyPersistedCredentials()
	}

	credsMap := make(map[string]InboundCredentials, len(cfg.Inbounds))

	for _, in := range cfg.Inbounds {
		creds, err := resolveInboundCredentials(in, persisted, genCfg, crossServerUsers[in.Tag])
		if err != nil {
			return nil, fmt.Errorf("inbound %q: %w", in.Tag, err)
		}
		credsMap[in.Tag] = creds
	}

	return credsMap, nil
}

func resolveInboundCredentials(
	in config.Inbound,
	persisted config.PersistedCredentials,
	genCfg GenerateConfig,
	referencedUsers map[string]bool,
) (InboundCredentials, error) {
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

		uc, err := generateUserCreds(in.Type)
		if err != nil {
			return InboundCredentials{}, fmt.Errorf("generate credentials for user %q: %w", user.Name, err)
		}
		creds.Users[user.Name] = uc
	}

	switch {
	case genCfg.FullReset:
		// FullReset uses empty persisted, so no extra users exist to preserve.
	case genCfg.Orphan:
		preserveReferencedUsers(persisted, in.Tag, &creds, referencedUsers)
	default:
		preserveExtraPersistedUsers(persisted, in.Tag, &creds)
	}

	if err := resolveRealityKeys(in, persisted, &creds); err != nil {
		return InboundCredentials{}, err
	}
	if err := resolveObfsPassword(in, persisted, &creds); err != nil {
		return InboundCredentials{}, err
	}
	resolveServerName(in, &creds)

	return creds, nil
}

func preserveExtraPersistedUsers(
	persisted config.PersistedCredentials,
	tag string,
	creds *InboundCredentials,
) {
	for name, uc := range persisted.InboundUsers[tag] {
		if _, declared := creds.Users[name]; !declared {
			creds.Users[name] = UserCreds{
				UUID:     uc.UUID,
				Password: uc.Password,
				Flow:     uc.Flow,
			}
		}
	}
}

func preserveReferencedUsers(
	persisted config.PersistedCredentials,
	tag string,
	creds *InboundCredentials,
	referencedUsers map[string]bool,
) {
	for name, uc := range persisted.InboundUsers[tag] {
		if _, declared := creds.Users[name]; declared {
			continue
		}
		if referencedUsers[name] {
			creds.Users[name] = UserCreds{
				UUID:     uc.UUID,
				Password: uc.Password,
				Flow:     uc.Flow,
			}
		}
	}
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

func generateUserCreds(inboundType string) (UserCreds, error) {
	switch inboundType {
	case inboundTypeVLESS:
		uuid, err := GenerateUUID()
		if err != nil {
			return UserCreds{}, fmt.Errorf("generate vless uuid: %w", err)
		}
		return UserCreds{UUID: uuid, Flow: "xtls-rprx-vision"}, nil
	case inboundTypeHysteria2:
		pw, err := GeneratePassword()
		if err != nil {
			return UserCreds{}, fmt.Errorf("generate hysteria2 password: %w", err)
		}
		return UserCreds{Password: pw}, nil
	default:
		return UserCreds{}, nil
	}
}

func resolveRealityKeys(
	in config.Inbound,
	persisted config.PersistedCredentials,
	creds *InboundCredentials,
) error {
	if in.Type != inboundTypeVLESS || in.TLS == nil || in.TLS.Reality == nil {
		return nil
	}

	if rk, ok := persisted.RealityKeys[in.Tag]; ok {
		publicKey := rk.PublicKey
		if publicKey == "" && rk.PrivateKey != "" {
			var deriveErr error
			publicKey, deriveErr = DerivePublicKey(rk.PrivateKey)
			if deriveErr != nil {
				return fmt.Errorf("derive public key for inbound %q: %w", in.Tag, deriveErr)
			}
		}
		creds.Reality = &RealityKeys{
			PrivateKey: rk.PrivateKey,
			PublicKey:  publicKey,
			ShortID:    rk.ShortID,
		}
		return nil
	}

	priv, pub, err := GenerateX25519KeyPair()
	if err != nil {
		return fmt.Errorf("generate reality key pair for inbound %q: %w", in.Tag, err)
	}
	shortID, err := GenerateShortID()
	if err != nil {
		return fmt.Errorf("generate reality short id for inbound %q: %w", in.Tag, err)
	}
	creds.Reality = &RealityKeys{
		PrivateKey: priv,
		PublicKey:  pub,
		ShortID:    []string{shortID},
	}
	return nil
}

func resolveObfsPassword(
	in config.Inbound,
	persisted config.PersistedCredentials,
	creds *InboundCredentials,
) error {
	if in.Type != inboundTypeHysteria2 || in.Obfs == nil {
		return nil
	}

	if pw, ok := persisted.ObfsPasswords[in.Tag]; ok {
		creds.ObfsPassword = pw
		return nil
	}

	pw, err := GeneratePassword()
	if err != nil {
		return fmt.Errorf("generate obfs password for inbound %q: %w", in.Tag, err)
	}
	creds.ObfsPassword = pw
	return nil
}

func resolveServerName(in config.Inbound, creds *InboundCredentials) {
	if in.TLS != nil {
		creds.ServerName = in.TLS.ServerName
		creds.ALPN = in.TLS.ALPN
	}
}

// resolveCertificates handles TLS certificate generation for hysteria2 inbounds.
// It reads existing certs, checks if they need regeneration, and generates new
// ones if needed.
func resolveCertificates(dir string, cfg config.Config, fullReset bool) ([]FileOutput, error) {
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

		needsRegen := fullReset
		if !needsRegen && certPEM != nil {
			cert, parseErr := parseCertPEM(certPEM)
			if parseErr != nil || CertNeedsRegeneration(cert, serverName) {
				needsRegen = true
			}
		}

		if certPEM == nil || keyPEM == nil || needsRegen {
			var err error
			certPEM, keyPEM, err = GenerateSelfSignedCertPEM(serverName)
			if err != nil {
				return nil, fmt.Errorf("generate cert for %q: %w", serverName, err)
			}
		}

		files = append(files,
			FileOutput{Path: certRelPath, Content: certPEM},
			FileOutput{Path: keyRelPath, Content: keyPEM},
		)
	}

	return files, nil
}

// addBoilerplate sets experimental options on the sing-box configuration.
// Cache file is disabled by default and must be explicitly enabled via config.
func addBoilerplate(opts *option.Options, cfg config.Config) {
	if cfg.Experimental != nil && cfg.Experimental.CacheFile != nil && cfg.Experimental.CacheFile.Enabled != nil &&
		*cfg.Experimental.CacheFile.Enabled {
		opts.Experimental = &option.ExperimentalOptions{
			CacheFile: &option.CacheFileOptions{Enabled: true},
		}
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

// crossServerUserRefs scans all configs and builds a map of which users are
// referenced by cross-server outbounds: targetServer -> inboundTag -> set of userNames.
func crossServerUserRefs(
	configs map[string]config.Config,
) map[string]map[string]map[string]bool {
	refs := make(map[string]map[string]map[string]bool)

	for sourceName, cfg := range configs {
		for _, out := range cfg.Outbounds {
			if out.Server == "" {
				continue
			}
			if out.Type != inboundTypeVLESS && out.Type != inboundTypeHysteria2 {
				continue
			}

			user := out.User
			if user == "" {
				user = sourceName
			}

			serverRefs, ok := refs[out.Server]
			if !ok {
				serverRefs = make(map[string]map[string]bool)
				refs[out.Server] = serverRefs
			}

			tagRefs, ok := serverRefs[out.Inbound]
			if !ok {
				tagRefs = make(map[string]bool)
				serverRefs[out.Inbound] = tagRefs
			}

			tagRefs[user] = true
		}
	}

	return refs
}

func generateWithDAG(
	projectRoot string,
	configs map[string]config.Config,
	order []string,
	genCfg GenerateConfig,
) ([]GenerateResult, error) {
	state := NewServerState()
	resultMap := make(map[string]GenerateResult, len(order))

	var allCrossServerUsers map[string]map[string]map[string]bool
	if genCfg.Orphan {
		allCrossServerUsers = crossServerUserRefs(configs)
	}

	for _, name := range order {
		var serverCrossUsers map[string]map[string]bool
		if allCrossServerUsers != nil {
			serverCrossUsers = allCrossServerUsers[name]
		}

		result, dirty, genErr := generateServerWithState(
			filepath.Join(projectRoot, name),
			name,
			configs[name],
			genCfg,
			state,
			serverCrossUsers,
		)
		if genErr != nil {
			return nil, fmt.Errorf("server %s: %w", name, genErr)
		}
		resultMap[name] = result

		for target := range dirty {
			if _, exists := resultMap[target]; exists {
				var targetCrossUsers map[string]map[string]bool
				if allCrossServerUsers != nil {
					targetCrossUsers = allCrossServerUsers[target]
				}

				result, _, regenErr := generateServerWithState(
					filepath.Join(projectRoot, target),
					target,
					configs[target],
					genCfg,
					state,
					targetCrossUsers,
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
	crossServerUsers map[string]map[string]bool,
) (GenerateResult, map[string]bool, error) {
	persisted, err := config.LoadPersistedCredentials(filepath.Join(dir, "config.json"))
	if err != nil {
		return GenerateResult{}, nil, fmt.Errorf("load persisted credentials: %w", err)
	}

	credsMap, err := resolveCredentials(cfg, persisted, genCfg, crossServerUsers)
	if err != nil {
		return GenerateResult{}, nil, fmt.Errorf("resolve credentials: %w", err)
	}

	for _, in := range cfg.Inbounds {
		state.StoreInboundType(serverName, in.Tag, in.Type)
		if in.ListenPort > 0 && in.ListenPort <= math.MaxUint16 {
			state.StoreListenPort(serverName, in.Tag, uint16(in.ListenPort))
		}
		mergeCredentialsIntoState(state, serverName, in.Tag, credsMap[in.Tag])
	}

	certFiles, err := resolveCertificatesWithState(dir, cfg, genCfg.FullReset, state, serverName)
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

	addBoilerplate(&opts, cfg)

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
	if len(existing.ALPN) == 0 && len(creds.ALPN) > 0 {
		existing.ALPN = creds.ALPN
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
	fullReset bool,
	state *ServerState,
	serverName string,
) ([]FileOutput, error) {
	files, err := resolveCertificates(dir, cfg, fullReset)
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

		pin, pinErr := ComputePinSHA256(certFile.Content)
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
