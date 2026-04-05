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
discover → load & parse → build DAG → topological sort → resolve & generate → post-process
```

1. **Discover** — recursively find all directories containing `cheburbox.json` (or `.cheburbox.jsonnet`)
2. **Load & Parse** — eval jsonnet if needed, parse cheburbox.json into Go structs, read existing config.json for persistence
3. **Build DAG** — outbound references to other servers create edges; detect cycles → error
4. **Topological Sort** — determine generation order (servers with no outgoing refs first)
5. **Resolve & Generate** — for each server in order: create cross-server users on targets, generate certs, build config.json, write to disk
6. **Post-process** — compile local rule-sets, validate with `sing-box check`

### Known Limitations

- **No circular dependencies.** If server A references server B and server B references server A, this is a cycle and will produce an error. Topology must be a DAG (star or tree pattern).

### Execution Model

Cheburbox runs locally on the developer machine. It reads all server directories in the project, generates config.json for each, and does not deploy (deployment is handled separately by `copy.sh` or similar).

### Implicit Server/Client Distinction

No explicit `role` field. A server is a "server" if it has inbounds. A "client" is just a server with outbounds referencing other servers and optionally a tun inbound. Cheburbox treats them identically.

## 3. cheburbox.json Schema

```jsonc
{
  "endpoint": "138.124.181.194",

  "log": {
    "level": "error",
    "timestamp": true
  },

  "dns": {
    "servers": [
      { "type": "local", "tag": "dns-local", "default_resolver": true },
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

### Inbound Details

- **users** — list of names (strings). Credentials (uuid/password) are generated or read from existing config.json (persistence).
- **vless tls.reality** — `private_key` and `public_key` generated via sing-box library (x25519). `short_id` persisted.
- **hysteria2 tls** — `server_name` binds to certificate CN/SAN. If `server_name` changes, certificate is regenerated. Multiple hysteria2 inbounds with different domains produce separate cert/key files (e.g., `cert_hy2-in.pem`, `key_hy2-in.pem`).
- **hysteria2 obfs** — password generated and persisted.
- **tun** — full sing-box tun config, no special handling. Just another inbound type.
- **Certificates** — self-signed, auto-generated if missing. Cheburbox uses `crypto/x509` + `crypto/ed25519` from Go stdlib.

### Outbound Details

- **type** — required: `direct`, `vless`, `hysteria2`, `urltest`, `selector`.
- **server** — (vless/hysteria2) target server directory name.
- **inbound** — (vless/hysteria2) target inbound tag on the target server.
- **user** — (vless/hysteria2) optional. Default: current server directory name.
- **endpoint** — (vless/hysteria2) optional override. Default: target server's `endpoint` field from its cheburbox.json.
- **flow** — (vless) default: `xtls-rprx-vision`. Explicit string `"null"` = omit field from generated config.
- **domain_resolver** — auto-filled from DNS server marked `default_resolver: true`. Fallback: first DNS with `detour: "direct"` or `type: "local"`.

### DNS Details

- Full DNS config as per sing-box schema, passed through.
- `default_resolver: true` on a DNS server marks it as the default `domain_resolver` for all outbounds.
- If no explicit `default_resolver`, fallback to first DNS server with `detour: "direct"` or `type: "local"`.

### Route Details

- `auto_detect_interface` — default: `true`, can be overridden.
- `default_domain_resolver` — auto-filled from `default_resolver` DNS server.
- `rule_sets` — remote rule-sets with URL, format, download_detour, update_interval.
- `custom_rule_sets` — list of tags for local rule-sets (extension.json → compiled to .srs).
- `rules` — route rules as per sing-box schema.
- Local rule-sets compiled via `sing-box rule-set compile` from sing-box library.
- DRY for shared rule-set definitions handled via jsonnet, not by cheburbox.

## 4. Jsonnet Integration

Cheburbox supports jsonnet as a preprocessing step:

1. If directory contains `.cheburbox.jsonnet`, cheburbox evaluates it with `--jpath <dir>` (default: `lib/` in project root).
2. Output is treated as `cheburbox.json`.
3. If both `.cheburbox.jsonnet` and `cheburbox.json` exist, `.cheburbox.jsonnet` takes precedence.
4. If only `cheburbox.json` exists, it is used directly.

This allows shared config parts (rule-set catalogs, DNS presets, route rules) to live in a `lib/` directory and be imported via `import "lib/route.jsonnet"`.

## 5. Persistence

Credentials are read from and written to `config.json` in each server directory.

### Read Order

When generating config for a server:
1. If `config.json` exists, parse it and extract all credentials.
2. If a credential is missing (new user, new inbound), generate it.

### What is Persisted

| Object | Key | Generation Method |
|--------|-----|-------------------|
| vless user (inbound) | `uuid` | sing-box library |
| hysteria2 user (inbound) | `password` | 24 bytes, base64 encoded |
| hysteria2 obfs | `password` | 24 bytes, base64 encoded |
| reality keypair | `private_key`, `public_key` | sing-box library (x25519) |
| reality short_id | hex string array | random 1-16 bytes, hex encoded |
| TLS cert/key (hysteria2) | `cert_<tag>.pem`, `key_<tag>.pem` | self-signed, CN = server_name |

### Cross-Server User Provisioning

When outbound references another server (e.g., `server: sp-p-2, inbound: vless-in, user: ru-p-2`):

1. Read target server's config.json.
2. Check if user `ru-p-2` exists in inbound `vless-in`.
3. If exists — extract credentials (uuid/password).
4. If not — generate credentials, add user to target server's inbound, write updated config.json.

This is why topological sort matters: the target server's config.json must be generated before the source server's.

### Certificate Lifecycle

- Certificates are stored as files in the server directory.
- Filename pattern: `cert_<inbound-tag>.pem`, `key_<inbound-tag>.pem` (for hysteria2 inbounds). For vless with reality, only keypair (in config.json, not files).
- On generation, cheburbox reads existing cert, checks CN/SAN against `tls.server_name`. If mismatch — regenerate.
- First generation: if no cert exists, create self-signed cert with CN = `tls.server_name`.

## 6. CLI Commands

```
cheburbox [global flags] <command> [command flags]

Global flags:
  --jpath <dir>         jsonnet library path (default: lib/)
  --project <dir>       project root (default: CWD)

Commands:

  generate [--server <name>] [--all] [--dry-run]
    Generate config.json for specified server(s).
    --all: all servers (default)
    --dry-run: stdout only, no file writes
    --skip-cert: do not generate certificates
    --skip-compile: do not compile rule-sets
    --force: regenerate all credentials (ignore persistence)

  links [--server <name>] [--user <name>] [--inbound <tag>] [--format json|uri]
    Export user configs.
    Default: all users on specified server/inbound.
    --format json: outbound configs in JSON
    --format uri (default): vless:// and hysteria2:// share links

  validate [--server <name>] [--all]
    Validate generated config.json via sing-box check.
    Also check consistency: all outbound refs resolve, no cycles, credentials present.

  diff [--server <name>]
    Show diff between current config.json and what would be generated.

  gen-cert [--server <name>] [--inbound <tag>]
    Explicit certificate generation/regeneration for hysteria2 inbound.

  init [--server <name>]
    Create template cheburbox.json in server directory.

  rule-set compile [--server <name>] [--input <file>] [--output <file>]
    Compile local rule-set (extension.json -> extension.srs).
    Default: find extension.json in server directory.
```

## 7. Auto-Generated Boilerplate

Cheburbox automatically adds to every generated config.json:

- `experimental.cache_file.enabled: true, path: "cache.db"` (unless explicitly disabled)
- `route.auto_detect_interface: true` (unless overridden in cheburbox.json)
- `route.default_domain_resolver` — from DNS server marked `default_resolver: true`
- `domain_resolver` on direct outbound — from default resolver DNS

## 8. Project Structure

### Cheburbox Source Code

```
cheburbox/
├── cmd/cheburbox/main.go
├── internal/
│   ├── config/
│   │   ├── cheburbox.go       # cheburbox.json Go structs
│   │   ├── load.go            # discover, jsonnet eval, parse
│   │   └── persistence.go     # read/write credentials from/to config.json
│   ├── generate/
│   │   ├── graph.go           # DAG build, topological sort, cycle detection
│   │   ├── server.go          # generate server config.json
│   │   ├── inbound.go         # vless, hysteria2, tun
│   │   ├── outbound.go        # direct, vless, hysteria2, urltest, selector
│   │   ├── dns.go             # dns section
│   │   ├── route.go           # route + rule-sets
│   │   └── certs.go           # TLS cert generation, validation, rotation
│   ├── links/
│   │   ├── vless.go           # vless:// URI builder
│   │   └── hysteria2.go       # hysteria2:// URI builder
│   ├── ruleset/
│   │   └── compile.go         # wrap sing-box rule-set compile
│   └── validate/
│       └── check.go           # wrap sing-box config check
├── go.mod
└── Makefile
```

### Dependencies

- `github.com/spf13/cobra` — CLI framework
- `github.com/google/go-jsonnet` — jsonnet evaluation
- `github.com/sagernet/sing-box` — Go library for:
  - `option` package — sing-box config Go structs (reuse, not rewrite)
  - UUID generation
  - X25519 keypair generation (reality)
  - Rule-set compile
  - Config check (`sing-box check`)
- Go stdlib: `crypto/x509`, `crypto/ed25519`, `encoding/pem` — self-signed certificate generation

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

- No circular dependencies between servers
- Outbound `server` references an existing server directory
- Outbound `inbound` references an existing inbound on target server
- No two inbounds on same server share the same `listen_port` and `listen` address
- No two hysteria2 inbounds on same server share the same `tls.server_name` (would conflict on cert files)
- All referenced DNS servers exist
- All referenced rule-set tags are defined
- `default_resolver: true` is set on at most one DNS server
