# Cheburbox — Design Document

## 1. Overview

Cheburbox is a CLI tool written in Go that manages sing-box configurations across multiple servers. It reads declarative `cheburbox.json` files from server directories, resolves cross-server dependencies, generates `config.json` for each server, and exports client connection links.

### Problem

Current workflow requires manual editing of sing-box `config.json` files across 5+ servers. This leads to:
- Massive boilerplate duplication (rule-sets, DNS, route rules are 90% identical)
- Manual credential management (uuid, passwords, x25519 keys, certificates)
- Manual cross-server user provisioning (when server A needs an outbound to server B, a user must be created on B)
- No single source of truth for infrastructure topology

### Solution

Declarative configuration (`cheburbox.json` per server) with automatic credential generation, cross-server dependency resolution via topological sort, and jsonnet for DRY shared config parts.

## 2. Architecture

### Pipeline

```
discover → load & parse → build DAG → topological sort → resolve & generate (in-memory) → batch write → post-process
```

1. **Discover** — find all direct child directories containing `cheburbox.json` (or `.cheburbox.jsonnet`) under the project root. Only one level deep.
2. **Load & Parse** — eval jsonnet if needed, parse cheburbox.json into cheburbox Go structs, read existing config.json for credential persistence.
3. **Build DAG** — outbound references to other servers create edges; detect cycles → error.
4. **Topological Sort** — determine generation order (servers with no outgoing refs first).
5. **Resolve & Generate** — for each server in order: create cross-server users on targets in memory, generate certs in memory, build config.json in memory. All processing happens in memory — no disk writes.
6. **Batch Write** — only after ALL servers in the generation set have been successfully processed, write all files (config.json, certs, .srs) to disk. If any server fails, nothing is written.
7. **Post-process** — validate with `sing-box check` on written configs.

### Known Limitations

- **No circular dependencies.** If server A references server B and server B references server A, this is a cycle and will produce an error. Topology must be a DAG (star or tree pattern).

### Execution Model

Cheburbox runs locally on the developer machine. It reads all server directories in the project, generates config.json for each, and does not deploy (deployment is handled separately by `copy.sh` or similar).

### Implicit Server/Client Distinction

No explicit `role` field. A server is a "server" if it has inbounds. A "client" is just a server with outbounds referencing other servers and optionally a tun inbound. Cheburbox treats them identically.

### Two-Pass Atomic Write

Generation uses a two-pass approach to ensure consistency:

- **Pass 1 (in-memory)**: All servers processed in topological order entirely in memory. Cross-server user provisioning adds users to in-memory target configs. Credentials, certs, and rule-sets are all generated in memory.
- **Pass 2 (batch write)**: Only after all servers succeed, write all files to disk atomically. If any server fails in pass 1, no files are modified.

### Two Sets of Structs

Cheburbox uses two distinct sets of Go structs:

- **Cheburbox structs** (`internal/config/cheburbox.go`): user-facing, simplified schema for `cheburbox.json` input. These are our own types with no sing-box dependency for unmarshaling.
- **Sing-box option structs** (`github.com/sagernet/sing-box/option`): used only for producing final `config.json` output. These require context-aware unmarshaling with registries.
- A conversion layer translates cheburbox structs → sing-box option structs during generation. The planned approach is to marshal cheburbox structs to JSON and unmarshal into sing-box option structs (leveraging their registry-based unmarshaling). This may be revised during Phase 2 implementation if the sing-box API supports direct struct construction.

This separation exists because sing-box option structs use `context.Context`-aware JSON unmarshaling with protocol registries, making them unsuitable for direct use as input types.

## 3. cheburbox.json Schema

```jsonc
{
  "version": 1,
  "endpoint": "138.124.181.194",

  "log": {
    "level": "error",
    "timestamp": true
  },

  "dns": {
    "servers": [
      { "type": "local", "tag": "dns-local" },
      { "type": "tls", "tag": "dns-remote", "server": "8.8.8.8", "server_port": 853, "detour": "direct" }
    ],
    "rules": [ ... ],
    "final": "dns-remote",
    "strategy": "prefer_ipv4"
  },

  "inbounds": [
    {
      "tag": "vless-in",
      "type": "vless",
      "listen_port": 443,
      "tls": {
        "reality": {
          "handshake": { "server": "spain.info", "server_port": 443 },
          "short_id": ["9b1f10c4"]
        }
      },
      "users": ["desktop", "Laptop", "Mobile"]
    },
    {
      "tag": "hy2-in",
      "type": "hysteria2",
      "listen_port": 443,
      "up_mbps": 1000,
      "down_mbps": 1000,
      "tls": {
        "server_name": "spain.info"
      },
      "obfs": { "type": "salamander" },
      "masquerade": { "type": "proxy", "url": "https://spain.info", "rewrite_host": true },
      "users": ["desktop"]
    },
    {
      "tag": "tun-in",
      "type": "tun",
      "interface_name": "sing-box",
      "address": ["172.19.0.1/30"],
      "mtu": 1500,
      "auto_route": true,
      "stack": "system",
      "endpoint_independent_nat": true,
      "exclude_interface": ["wt0", "awg0", "awg1"],
      "route_exclude_address": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
    }
  ],

  "outbounds": [
    { "type": "direct", "tag": "direct" },
    {
      "type": "vless",
      "tag": "sp-p-2-vless",
      "server": "sp-p-2",
      "inbound": "vless-in",
      "user": "ru-p-2",
      "flow": "xtls-rprx-vision",
      "endpoint": "1.2.3.4"
    },
    {
      "type": "hysteria2",
      "tag": "sp-p-2-hy",
      "server": "sp-p-2",
      "inbound": "hy2-in",
      "user": "ru-p-2"
    },
    {
      "type": "urltest",
      "tag": "proxy",
      "outbounds": ["sp-p-2-vless", "sp-p-2-hy", "fin-p-2-hy"],
      "url": "https://www.gstatic.com/generate_204",
      "interval": "3m"
    }
  ],

  "route": {
    "final": "direct",
    "auto_detect_interface": true,
    "rule_sets": { ... },
    "custom_rule_sets": ["extension", "fastly"],
    "rules": [ ... ]
  }
}
```

### Top-Level Fields

- **version** — required, must be `1`. Reserved for future schema evolution.
- **endpoint** — the public IP or domain name of this server. Required for servers with inbounds (other servers use it to connect). Used as default `server` address in outbounds that reference this server.

### Inbound Details

- **users** — list of names (strings). Credentials (uuid/password) are generated or read from existing config.json (persistence).
- **vless tls.reality** — `private_key` and `public_key` generated via Go stdlib `crypto/ecdh` (x25519). `short_id` persisted.
- **hysteria2 tls** — `server_name` binds to certificate SAN. If `server_name` changes, certificate is regenerated. Multiple hysteria2 inbounds with different domains produce separate cert/key files (e.g., `cert_hy2-in.pem`, `key_hy2-in.pem`).
- **hysteria2 obfs** — password generated and persisted.
- **tun** — full sing-box tun config, no special handling. Just another inbound type.
- **Certificates** — self-signed, auto-generated if missing. Cheburbox uses `crypto/x509` + `crypto/ed25519` from Go stdlib.
- Certificate paths in generated config.json use relative filenames only (e.g., `cert_hy2-in.pem`). sing-box resolves relative to config.json location.

### Extensible Inbound Architecture

Inbound generators follow a plugin-like interface to allow adding new protocol types (shadowsocks, trojan, etc.) in future phases without refactoring. First phase implements: vless, hysteria2, tun.

### Outbound Details

- **type** — required: `direct`, `vless`, `hysteria2`, `urltest`, `selector`.
- **server** — (vless/hysteria2) target server directory name (used as server identifier).
- **inbound** — (vless/hysteria2) target inbound tag on the target server.
- **user** — (vless/hysteria2) optional. Default: current server directory name.
- **endpoint** — (vless/hysteria2) optional override. Default: target server's `endpoint` field from its cheburbox.json.
- **flow** — (vless) always explicit in cheburbox.json. Default: `xtls-rprx-vision`. Explicit string `"null"` = omit field from generated config.
- **pin-sha256** — (hysteria2 outbound) auto-computed by cheburbox from the target server's certificate public key. Not specified in cheburbox.json.
- **selector** — `type: "selector"`, `tag`, `outbounds` (list of outbound tags). No additional fields.

```jsonc
{
  "type": "selector",
  "tag": "proxy",
  "outbounds": [
    "de-p-1-vless",
    "de-p-1-hy",
    "sp-p-2-vless",
    "ams-p-1-vless",
    "sp-p-2-hy",
    "fin-p-2-hy",
    "ams-p-1-hy",
    "fin-p-1-vless"
  ]
}
```

### Log Details

- Full log config as per sing-box schema, passed through without parsing.
- No cheburbox-specific fields in the log section.

### DNS Details

- Full DNS config fully parsed into cheburbox Go structs, matching the sing-box DNS schema.
- DNS section is mandatory in every cheburbox.json.
- Cheburbox structs model the complete sing-box DNS schema to enable validation.
- No `default_resolver` concept. Each outbound that needs a domain resolver specifies it explicitly, or relies on `default_domain_resolver` in the route section.

### Route Details

- `auto_detect_interface` — default: `true`, can be overridden.
- `default_domain_resolver` — set explicitly in cheburbox.json to the tag of a DNS server to use as default domain resolver. If omitted, no default is set.
- `rule_sets` — remote rule-sets with URL, format, download_detour, update_interval. Fully parsed into cheburbox structs.
- `custom_rule_sets` — list of tags for local rule-sets (extension.json → compiled to .srs).
- `rules` — route rules fully parsed into cheburbox Go structs (not raw passthrough).
- Local rule-sets compiled via sing-box `common/srs` package. Source format: standard sing-box rule-set JSON. Output: `.srs` file in the same server directory.
- DRY for shared rule-set definitions handled via jsonnet, not by cheburbox.
- Rule-set compilation happens automatically during `generate` for all `*.json` rule-set source files found in the server directory.

## 4. Jsonnet Integration

Cheburbox supports jsonnet as a preprocessing step:

1. If directory contains `.cheburbox.jsonnet`, cheburbox evaluates it with `--jpath <dir>` (default: `lib/` in project root).
2. Output is treated as `cheburbox.json`.
3. If both `.cheburbox.jsonnet` and `cheburbox.json` exist, `.cheburbox.jsonnet` takes precedence.
4. If only `cheburbox.json` exists, it is used directly.

This allows shared config parts (rule-set catalogs, DNS presets, route rules) to live in a `lib/` directory and be imported via `import "lib/route.jsonnet"`.

## 5. Persistence

Credentials are read from and written to `config.json` in each server directory. The generated `config.json` is a pure sing-box config with no cheburbox metadata.

### Read Order

When generating config for a server:
1. If `config.json` exists, parse it into sing-box option structs and extract all credentials.
2. If a credential is missing (new user, new inbound), generate it.

Credential extraction uses sing-box option structs (the same structs used for output generation), not raw JSON traversal.

### User Lifecycle

- **Additive by default**: cheburbox only adds users and credentials. Users/credentials that exist in config.json but are not listed in cheburbox.json are preserved.
- **`--clean` flag**: when passed to `generate`, removes users/credentials that exist in config.json but are no longer declared in cheburbox.json. This applies to both local users and cross-server provisioned users.

### What is Persisted

| Object | Key | Generation Method |
|--------|-----|-------------------|
| vless user (inbound) | `uuid` | `github.com/gofrs/uuid/v5` (`uuid.NewV4()`, random) |
| hysteria2 user (inbound) | `password` | 24 bytes, base64 encoded |
| hysteria2 obfs | `password` | 24 bytes, base64 encoded |
| reality keypair | `private_key`, `public_key` | Go stdlib `crypto/ecdh` (x25519) |
| reality short_id | hex string array | random 1-16 bytes, hex encoded |
| TLS cert/key (hysteria2) | `cert_<tag>.pem`, `key_<tag>.pem` | self-signed, SAN = server_name |

### Cross-Server User Provisioning

When outbound references another server (e.g., `server: sp-p-2, inbound: vless-in, user: ru-p-2`):

1. Look up target server's in-memory config (already generated by topological order).
2. Check if user `ru-p-2` exists in inbound `vless-in`.
3. If exists — extract credentials (uuid/password).
4. If not — generate credentials, add user to target server's in-memory inbound config.

This is why topological sort matters: the target server's config must be generated (in memory) before the source server's. When using `--server`, all upstream dependencies are generated transitively.

A single user (e.g., `ru-p-2`) may exist in multiple inbounds (vless and hysteria2) on the same target server. This is valid and expected.

### Certificate Lifecycle

- Certificates are stored as files in the server directory.
- Filename pattern: `cert_<inbound-tag>.pem`, `key_<inbound-tag>.pem` (for hysteria2 inbounds). For vless with reality, only keypair (in config.json, not files).
- On generation, cheburbox reads existing cert from disk, checks SAN against `tls.server_name`. If mismatch — regenerate.
- First generation: if no cert exists, create self-signed cert with SAN = `tls.server_name`. Certificates use SAN (Subject Alternative Name), not CN (deprecated).

## 6. CLI Commands

```
cheburbox [global flags] <command> [command flags]

Global flags:
  --jpath <dir>         jsonnet library path (default: lib/)
  --project <dir>       project root (default: CWD)

Commands:

  generate [--server <name>] [--clean] [--dry-run]
    Generate config.json for specified server(s).
    Default (no flags): all servers.
    --server <name>: generate only this server and its upstream dependencies (transitively).
      All dependencies must be declared (cheburbox.json exists with required inbounds).
    --clean: remove users/credentials from generated config.json that are no longer
      declared in cheburbox.json. Without this flag, generation is additive only.
    --dry-run: stdout only, no file writes. Output: JSON array of objects, each with
      {"server": "<name>", "files": [{"path": "<relative>", "content": "<string>"}]}.
      Binary files (.srs) are base64-encoded.

  links [--server <name>] [--user <name>] [--inbound <tag>] [--format json|uri]
    Export user configs from generated config.json.
    Requires config.json to exist — run generate first.
    Default (no flags): export all users from all servers.
    --server <name>: restrict to specific server.
    --format json: ready-to-use sing-box outbound configs for client config.
    --format uri (default): vless:// and hysteria2:// share links.
      Hysteria2 links use pin-sha256= parameter (certificate public key hash),
      not insecure=1.
    Only vless and hysteria2 inbounds produce links (tun and others are skipped).

  validate [--server <name>] [--all]
    Two-phase validation:
    1. Consistency checks: all outbound refs resolve, no cycles, credentials present.
    2. sing-box check on existing config.json files (skipped if config.json missing).

  diff [--server <name>]
    Show unified diff between current config.json and what would be generated.
    Implemented as in-memory generation + unified diff against disk file.

  init [--server <name>]
    Create a full example cheburbox.json template in server directory.

  rule-set compile [--server <name>] [--input <file>] [--output <file>]
    Compile local rule-set (extension.json -> extension.srs).
    Default: find extension.json in server directory.
```

## 7. Auto-Generated Boilerplate

Cheburbox automatically adds to every generated config.json:

- `experimental.cache_file.enabled: true, path: "cache.db"` (unless explicitly disabled)
- `route.auto_detect_interface: true` (unless overridden in cheburbox.json)
- `route.default_domain_resolver` — if set in cheburbox.json route section, passed through to generated config

## 8. Project Structure

### Cheburbox Source Code

```
cheburbox/
├── cmd/cheburbox/
│   └── main.go                # CLI entry point and command logic
├── config/
│   ├── cheburbox.go            # cheburbox.json Go structs (our own types)
│   ├── load.go                 # discover, jsonnet eval, parse
│   └── persistence.go          # read credentials from config.json
├── generate/
│   ├── graph.go                # DAG build, topological sort, cycle detection
│   ├── server.go               # orchestrate server config generation
│   ├── convert.go              # cheburbox structs → sing-box option structs
│   ├── inbound.go              # vless, hysteria2, tun generators
│   ├── outbound.go             # direct, vless, hysteria2, urltest, selector generators
│   ├── dns.go                  # dns section full parsing + domain_resolver auto-fill
│   ├── route.go                # route + rule-sets full parsing
│   ├── certs.go                # TLS cert generation, validation, rotation
│   └── credentials.go          # UUID, password, x25519 keypair generation
├── links/
│   ├── vless.go                # vless:// URI builder
│   └── hysteria2.go            # hysteria2:// URI builder
├── ruleset/
│   └── compile.go              # wrap sing-box common/srs compile
├── validate/
│   └── check.go                # consistency checks + sing-box config check
├── go.mod
└── Makefile
```

### Dependencies

- `github.com/spf13/cobra` — CLI framework
- `github.com/google/go-jsonnet` — jsonnet evaluation
- `github.com/sagernet/sing-box` v1.13.5 — direct dependency from GitHub:
  - `option` package — sing-box config Go structs (for output generation only)
  - `common/srs` package — rule-set compile (`srs.Write`)
  - `include` + root package — config check (`box.New` with `include.Context`)
  - `constant` package — enum values (RuleSetVersion, etc.)
- `github.com/gofrs/uuid/v5` — UUID generation (`uuid.NewV4()`, random UUID v4; v5 is the Go module major version)
- Go stdlib: `crypto/ecdh` (x25519 keypairs), `crypto/x509`, `crypto/ed25519`, `encoding/pem` — certificate generation

### Working Project Layout

```
sing-box/
├── lib/                         # jsonnet libraries (user-managed)
│   ├── rule-sets.jsonnet
│   ├── dns.jsonnet
│   └── route.jsonnet
├── ams-p-1/
│   ├── .cheburbox.jsonnet       # import "lib/route.jsonnet"
│   ├── config.json              # generated by cheburbox
│   ├── cert.pem / key.pem       # generated by cheburbox
│   └── extension.json           # custom local rule-set source
├── de-p-1/
├── fin-p-2/
├── ru-p-2/
├── sp-p-2/
├── home/
├── copy.sh                      # deployment script (separate from cheburbox)
└── docker-compose.yml
```

## 9. Validation Rules

Cheburbox checks at generation time:

- `version` field is present and equals `1`
- No circular dependencies between servers
- Outbound `server` references an existing server directory (direct child of project root)
- Outbound `inbound` references an existing inbound on target server
- No two hysteria2 inbounds on same server share the same `tls.server_name` (would conflict on cert files)
- DNS section is present
- `endpoint` is present for servers with inbounds

## 10. Implementation Phases

### Phase 1 — Foundation

Project skeleton and configuration loading. No generation logic.

- CLI setup with cobra (global flags: `--project`, `--jpath`)
- Cheburbox Go structs for full `cheburbox.json` schema (`internal/config/cheburbox.go`)
- Discovery: find server directories with `cheburbox.json` or `.cheburbox.jsonnet`
- Jsonnet evaluation via `github.com/google/go-jsonnet`
- Parse cheburbox.json into cheburbox structs
- Basic `generate` command: reads config, validates required fields, outputs minimal skeleton
- Unit tests for config parsing and discovery

### Phase 2 — Single-Server Generation

Full config generation for a single server (no cross-server dependencies).

- Credential generation: UUID v4 (`gofrs/uuid/v5`), passwords (24 bytes base64), x25519 keypairs (`crypto/ecdh`), short_id
- Inbound generators: vless (with reality), hysteria2 (with TLS certs, obfs, masquerade), tun (passthrough)
- Outbound generators: direct, vless, hysteria2 (with auto-computed pin-sha256), urltest, selector
- DNS section: full parsing matching sing-box schema
- Route section: full parsing, rule-sets, custom rule-sets
- Conversion layer: cheburbox structs → JSON → sing-box option structs (may be revised based on sing-box API investigation)
- Certificate generation: self-signed ed25519 certs via `crypto/x509` + `crypto/ed25519` with SAN = server_name
- Certificate lifecycle: read existing cert, check SAN, regenerate on mismatch
- Persistence: read credentials from existing `config.json` via sing-box option structs
- Auto-generated boilerplate: cache_file, auto_detect_interface
- `--clean` flag support
- Unit tests for all generators and credential logic

### Phase 3 — Rule-Sets

Local rule-set compilation.

- Wrap sing-box `common/srs` package for `.json` → `.srs` compilation
- Auto-compile all `*.json` rule-set source files in server directory during `generate`
- Standalone `rule-set compile` command with `--server`, `--input`, `--output` flags
- Tests with sample rule-set JSON

### Phase 4 — Validation

Config validation without generation.

- Consistency checks: outbound refs resolve, no cycles, credentials present, DNS present, `endpoint` for servers with inbounds, no duplicate hysteria2 `server_name`
- sing-box config check via Go API (`box.New` with `include.Context`)
- `validate` command with `--server` and `--all` flags
- Tests with valid and invalid configs

### Phase 5 — Multi-Server DAG

Cross-server dependency resolution.

- DAG construction from outbound `server` references
- Topological sort with cycle detection
- Cross-server user provisioning (add users to target server in-memory configs)
- Batch write: two-pass approach (in-memory generation, then atomic disk write)
- `--server` flag: generate specified server and transitive upstream dependencies
- `--dry-run`: stdout JSON output, no disk writes (binary files base64-encoded)
- Integration tests with multi-server project layouts

### Phase 6 — Utility Commands

Quality-of-life commands.

- `diff` command: in-memory generation + unified diff against disk `config.json`
- `init` command: create example `cheburbox.json` template in server directory
- Tests for diff output and init templates

### Phase 7 — Links

Client connection link export.

- `links` command with `--server`, `--user`, `--inbound`, `--format` flags
- `--format uri` (default): `vless://` and `hysteria2://` share links
- `--format json`: ready-to-use sing-box outbound configs
- Hysteria2 links use `pin-sha256=` (certificate public key hash), not `insecure=1`
- Only vless and hysteria2 inbounds produce links (tun and others skipped)
- Tests with sample generated configs

### Phase 1.1 — Foundation Cleanup

Post-implementation fixes identified after Phase 1 review.

- Replace custom `containsString` helper in `internal/config/load_test.go` with `strings.Contains` from stdlib.
- Review `Route` type: currently `*Route` (pointer, optional). If route section is always present in practice, consider changing to value type. Decision deferred to Phase 2 planning.
- `loadServer` function is intentionally unexported. Public API is `LoadServerWithJsonnet`. Credential persistence in Phase 2 will read existing `config.json` via sing-box option structs, not through this loader.

### Implementation Notes

- **sing-box option struct API**: The `github.com/sagernet/sing-box/option` package uses registry-based `context.Context`-aware JSON unmarshaling. Before Phase 2, investigate whether sing-box option structs can be constructed programmatically (direct field assignment) or require marshal→unmarshal through the registry. This determines the conversion layer architecture.
