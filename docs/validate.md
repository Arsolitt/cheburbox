# Validate

> Static and runtime validation of cheburbox projects without producing any output files.

## Table of Contents

- [What validate does](#what-validate-does)
- [Usage](#usage)
- [Flags](#flags)
- [Requirements](#requirements)
- [What gets checked](#what-gets-checked)
- [What doesn't get checked](#what-doesnt-get-checked)
- [Common errors](#common-errors)
- [Exit codes](#exit-codes)

## What validate does

`cheburbox validate` is a read-only sibling of [`generate`](./generate.md). It writes no files. Validation runs in two phases:

**Phase 1 — static analysis of `cheburbox.json`.**
All servers in the project are loaded into memory. Cheburbox builds the cross-server dependency graph (cycles and self-references rejected), reapplies schema validation per server, checks for `hysteria2` `tls.server_name` collisions inside each server, validates `urltest` / `selector` group references against intra-server outbound tags, and verifies that every cross-server outbound's `inbound` tag actually exists on the referenced target server.

**Phase 2 — sing-box config check on each generated `config.json`.**
For every server with a previously generated `<server>/config.json`, cheburbox parses it through sing-box's registry-aware decoder, then constructs and immediately closes a `box.New(opts)` instance. This mirrors the semantics of the `sing-box check` command. If a server has no generated `config.json` yet (i.e. you have not run `generate` for it), Phase 2 is skipped for that server only and a warning is emitted — Phase 1 still runs and the server is reported as PASS.

Servers are reported in alphabetical order regardless of input order.

## Usage

```shell
cheburbox validate [flags]
```

Examples:

```shell
# Validate every discovered server.
cheburbox validate

# Validate a single server and its transitive cross-server dependencies.
cheburbox validate --server srv-a
```

When `--server` is set, the project is loaded in full (so the dependency graph is complete), but only the named server and the servers it transitively references are validated and reported.

## Flags

| Flag | Type | Default | Purpose |
| --- | --- | --- | --- |
| `--server` | string | `""` | Validate only this server and its transitive dependencies. Empty means validate every discovered server. |
| `--project` | string | CWD | Project root containing per-server child directories. Inherited persistent flag. |
| `--jpath` | string | `lib` | Jsonnet library search path, resolved relative to `--project` (or absolute). Inherited persistent flag. |

## Requirements

No external `sing-box` binary is required. Cheburbox links sing-box as a Go library and runs the equivalent of `sing-box check` in-process. Installing the cheburbox binary (see [installation](./installation.md)) is sufficient.

The Phase 2 check changes the working directory into each server directory before parsing so that relative paths inside `config.json` (for example, `certs/<server_name>.crt`) resolve correctly. The directory is restored afterwards.

## What gets checked

| Phase | Check | Source |
| --- | --- | --- |
| 1 | `cheburbox.json` (or `.cheburbox.jsonnet`) loads and parses | per-server load |
| 1 | Schema constraints: `version == 1`, `dns` non-empty, `endpoint` present when inbounds defined, `listen_port` in `[0, 65535]` | reapplied during Phase 1 |
| 1 | Dependency graph builds without self-references or cycles | reported as a single `(global)` failure if it fails |
| 1 | Two `hysteria2` inbounds in the same server do not share `tls.server_name` (would collide on cert files) | per-server |
| 1 | `urltest` / `selector` outbound `outbounds` lists reference only outbound tags defined on the same server (groups are intra-server only) | per-server |
| 1 | Each cross-server outbound's `inbound` tag exists on the referenced target server. Targets outside the loaded scope (e.g. when `--server` narrows it) are skipped silently | per-server |
| 2 | `<server>/config.json` parses through sing-box's registry-aware decoder and `box.New(opts)` accepts it | per-server, skipped with warning if `config.json` is missing |

If Phase 1 produces a global error (cycle or unresolvable cross-server reference at graph-build time), the result list collapses to a single entry with `Server == "(global)"` and Phase 2 is not run at all.

## What doesn't get checked

Validation is a static and offline check. It does not:

- Make any network connection — TLS handshakes against real peers are not attempted.
- Probe runtime behavior, routing decisions, or DNS resolution.
- Verify that listeners can actually bind to the configured `listen_port`.
- Re-derive or re-validate persisted credentials beyond what sing-box's own decoder enforces.

## Common errors

| Output | Cause |
| --- | --- |
| `FAIL  (global): cycle detected in server dependencies` | Cross-server outbounds form a cycle. Phase 2 is skipped. |
| `FAIL  (global): server X has a self-referencing outbound Y` | An outbound on server X has `server: X`. |
| `FAIL  <server>: unsupported version N (want 1)` | `version` field is not `1` (or is `0` / missing). |
| `FAIL  <server>: dns section is required: at least one dns server must be defined` | The server's `dns` block is empty or absent. |
| `FAIL  <server>: endpoint is required when inbounds are defined` | Server defines inbounds but no `endpoint`. |
| `FAIL  <server>: hysteria2 inbounds Y and Z share the same tls.server_name S (would conflict on cert files)` | Two `hysteria2` inbounds on the same server have identical `tls.server_name`. |
| `FAIL  <server>: outbound "y" references inbound "t" on server "z", but no such inbound exists` | A cross-server outbound names a target inbound tag that does not exist on the target server. |
| `FAIL  <server>: <sing-box decoder error>` | Phase 2 — sing-box rejected the previously generated `config.json`. Usually means manual edits to the file or a sing-box upstream incompatibility. |
| `WARN  <server>: skipped sing-box check: <server>/config.json not found` | No prior `generate` for this server. Phase 1 still ran; not a failure. |

See [configuration](./configuration.md) for the full schema.

## Exit codes

- `0` — every reported server passed Phase 1 (warnings allowed). An empty project (no servers discovered) also exits `0` after printing `no servers found in project`.
- `1` — one or more servers had Phase 1 or Phase 2 errors. The CLI prints `Error: validation failed` to stderr.
