# Architecture

> How `cheburbox` is structured, why it is designed that way, and the behavioral quirks that follow from those decisions.

## Table of Contents

- [Overview](#overview)
- [Two layers of types](#two-layers-of-types)
- [Two-pass atomic generation](#two-pass-atomic-generation)
- [Cross-server reference DAG](#cross-server-reference-dag)
- [Credentials persistence](#credentials-persistence)
- [Validation pipeline](#validation-pipeline)
- [Rule-set compilation](#rule-set-compilation)
- [Pin SHA-256 for share links](#pin-sha-256-for-share-links)
- [Package layout](#package-layout)
- [Gotchas](#gotchas)

## Overview

`cheburbox` is a declarative-config compiler for [sing-box](https://sing-box.sagernet.org/). It reads a multi-server project (one `cheburbox.json` or `.cheburbox.jsonnet` per server directory), resolves cross-server references (where one server's outbound peer is another server's user), generates a per-server `config.json` plus any required certificates and rule-set binaries, and validates the result.

Three properties drive the design:

1. **Multi-server with cross-references.** Servers form a directed graph: an outbound on server A can reference a user U on server B's inbound. Generation is ordered by topological sort, with auto-provisioning of users that an outbound references but the target server didn't declare.
2. **Credential persistence.** UUIDs, passwords, x25519 keypairs, Reality short IDs, and obfs passwords are read back from the previous `config.json` on every run. Regenerating them blindly would invalidate already-distributed client credentials, so cheburbox preserves them by default.
3. **Atomic two-pass writes.** All servers are processed entirely in memory first; disk writes happen only after every server succeeds. A failure on server N never leaves servers 1..N-1 partially written.

The CLI does not shell out to `sing-box`. Validation links sing-box as a Go library and constructs `box.New(opts)` in-process. There is no external binary requirement at any step.

## Two layers of types

A frequent source of confusion for contributors: the project juggles two distinct sets of Go types. They look similar but are NOT interchangeable.

| Layer | Package | Purpose | Unmarshal |
| --- | --- | --- | --- |
| 1 | `config.*` (`Config`, `Inbound`, `Outbound`, `RealityConfig`, `User`, ...) | The user-facing `cheburbox.json` schema, plain JSON tags | Standard `encoding/json` |
| 2 | `github.com/sagernet/sing-box/option.*` (`Options`, `Inbound`, `VLESSInboundOptions`, ...) | The output `config.json` shape that sing-box itself consumes | Context-aware via `include.Context()` with protocol registry |

Layer 1 is intentionally simplified: a single `endpoint` field on the server, named user objects, declarative `custom_rule_sets`. Layer 2 is what sing-box requires — and because its option types use registry-driven unmarshaling, they cannot be used directly as the input format.

Generation translates Layer 1 into Layer 2 via builder helpers in `generate/`: `BuildInbound`, `BuildOutbound`, `ConvertDNS`, `ConvertRoute`. The final marshal uses `singjson.MarshalContext` + `json.Indent` for pretty output.

> **Note:** When extending the schema, add fields to Layer 1 only. The reverse direction — adding things to Layer 2 — is meaningless because sing-box owns those structs.

See [`./configuration.md`](./configuration.md) for the Layer 1 schema reference and [`./generate.md`](./generate.md) for how the translation runs.

## Two-pass atomic generation

The CLI guarantees that a failed run does not leave the project half-written.

**Pass 1 (in-memory):**

1. `Discover` lists child directories with a `cheburbox.json` or `.cheburbox.jsonnet`.
2. `BuildGraph` constructs the cross-server dependency DAG and rejects cycles or self-references.
3. `TopologicalSort` orders servers so leaves (those with no outbound dependencies) come first.
4. For each server in order, `generateServerWithState` produces a `GenerateResult` (the rendered `config.json` bytes plus any cert/rule-set FileOutputs). Cross-server users discovered along the way may mark earlier targets dirty; dirty servers are re-run in the same pass.
5. All results are accumulated in `resultMap[name]`.

**Pass 2 (disk):**

If, and only if, Pass 1 completes for every server, the CLI's `writeResults` iterates `resultMap` and writes files. Files are written with mode `0644`; directories with mode `0750`. Dry-run skips Pass 2 entirely (`TestGenerateDryRunNoDiskWrite` enforces this).

> **Note:** Rule-set `.srs` compilation is the one exception to "no disk writes in Pass 1." See [Rule-set compilation](#rule-set-compilation) below.

## Cross-server reference DAG

Each server is a graph node. An outbound on server A whose `server` field names server B creates a directed edge A → B (dependent → dependency). `BuildGraph` enforces three rules:

- A self-reference (`server X has a self-referencing outbound Y`) is rejected.
- A reference to an unknown server (`outbound Y references unknown server Z`) is rejected.
- A cycle in the dependency graph (`cycle detected in server dependencies`) is rejected via DFS coloring.

`TopologicalSort` is Kahn's algorithm using `inDegree[edge.From]++`, then enqueueing nodes with `inDegree == 0` first. The orientation means **leaves are processed first**: a server with no outbound dependencies is generated before any server that points to it.

When an outbound on A targets B with a user U that B did not declare, `provisionCrossServerUsers` calls `ServerState.EnsureUser(B, tag, U)` to generate credentials on B's inbound. B is marked dirty and re-run by `generateWithDAG` so its `config.json` reflects the auto-provisioned user.

The default-user fallback: an outbound with empty `user` resolves to the **source server's directory name**. So a server `proxy-server` whose outbound omits `user` will reference user `proxy-server` on the target.

The `--orphan` flag prunes any persisted user on a server that is neither declared in that server's `cheburbox.json` nor referenced by another server's cross-server outbound (with default-user fallback applied).

## Credentials persistence

Cheburbox does **not** regenerate credentials on every run. On each invocation, `generateServerWithState` calls `config.LoadPersistedCredentials(<server>/config.json)`, which:

1. Parses the previous output with sing-box's `include.Context()`-aware decoder.
2. Walks `Inbounds` and extracts:
   - VLESS users → `{UUID, Flow}`
   - Hysteria2 users → `{Password}`
   - Reality block (only when `reality.enabled`) → `{private_key, short_id}`
   - Hysteria2 obfs → password
3. Returns empty credentials (no error) if `config.json` is missing.

Resolution is per-user: persisted credentials win verbatim if present; otherwise fresh ones are generated. The Reality public key is **not** stored — it is derived from the private key on demand. By default, undeclared users present in the previous `config.json` are also preserved (this is what protects auto-provisioned cross-server users from being deleted).

Cryptographic generators:

| Field | Generator |
| --- | --- |
| UUID | `gofrs/uuid` v5 `NewV4` (reads `/dev/urandom`) |
| Password | `crypto/rand` 24 bytes, base64 std |
| X25519 keypair | `crypto/ecdh` |
| Reality short ID | `crypto/rand` 8 bytes, hex |
| Self-signed cert | Ed25519 + `crypto/x509` |

`--full-reset` is the explicit opt-in to wipe persisted state and regenerate everything (and force cert regeneration regardless of SAN match). It is mutually exclusive with `--orphan`. **Why this matters:** regenerating credentials silently would break every already-deployed client, which is why preservation is the default and reset is gated behind a named flag.

For deterministic output, `buildVLESSUsers` and `buildHysteria2Users` sort users alphabetically by name before emitting.

See [`./generate.md`](./generate.md) for the full credentials lifecycle.

## Validation pipeline

`cheburbox validate` runs in two phases (`validate/check.go runPhase1AndPhase2`):

**Phase 1 — static analysis (cross-server, no sing-box):**

- Build the DAG (cycle / self-reference / unknown-target detection).
- Check schema basics that aren't already caught by `Validate()`.
- Detect Hysteria2 inbounds on the same server sharing a `tls.server_name` (which would conflict on cert files).
- Verify that `urltest` / `selector` group `outbounds` reference tags defined on the **same** server (cross-server tags are not supported in groups).
- Verify cross-server outbound → inbound tag references resolve.

Global Phase 1 errors (e.g., a cycle) short-circuit Phase 2.

**Phase 2 — sing-box check, in-process:**

For each generated `config.json`, `singBoxCheck`:

1. Chdirs into the server directory so relative paths in the config (`certs/<name>.crt`) resolve.
2. Parses with `include.Context()`-aware `UnmarshalExtendedContext`.
3. Calls `box.New(opts)` and immediately `Close`s it.
4. Defers chdir-back.

If `<server>/config.json` is missing (no prior `generate`), Phase 2 emits a Warning ("skipped sing-box check: ...") rather than a hard failure; the server still reports PASS overall.

The two phases are decoupled by design: static analysis exercises cross-server semantics that sing-box itself cannot see; Phase 2 exercises full sing-box semantics on each generated artifact.

See [`./validate.md`](./validate.md) for command details.

## Rule-set compilation

The `ruleset` package compiles JSON rule-set sources at `<server>/<name>.json` into binary `.srs` files at `<server>/rule-set/<name>.srs`, using sing-box's `srs.Write`. The version field is optional (defaults to `RuleSetVersionCurrent`).

Discovery only counts files whose name (without extension) appears in `route.custom_rule_sets`. The reserved filenames `cheburbox.json` and `config.json` are always ignored, even if listed. Custom rule-set entries with no matching `<name>.json` source are silently skipped.

Compilation has a **disk side-effect**: `compileRuleSets` calls `os.Create` + `srs.Write` directly, then re-reads the `.srs` to package as a `FileOutput`. This means rule-set `.srs` files exist on disk before the atomic write boundary in Pass 2. If a later step fails, orphaned `.srs` files may remain.

The standalone `cheburbox rule-set compile --server X` command exists for the case where you want to recompile rule-sets without regenerating `config.json`. The same compilation also runs automatically inside `cheburbox generate`.

See [`./rule-set.md`](./rule-set.md) for usage.

## Pin SHA-256 for share links

`generate.ComputePinSHA256` was promoted from package-private to exported (commit `6fbea30`) so the `links` package can reuse it.

Format: `sha256/<base64-rawurl>`, where the payload is `sha256(MarshalPKIXPublicKey(cert.PublicKey))`.

Three call sites:

| Call site | Use |
| --- | --- |
| `generate/outbound.go` | Cross-server Hysteria2 outbound's `certificate_public_key_sha256` byte array |
| `links/hysteria2.go` (URI) | `pinSHA256` query parameter |
| `links/hysteria2.go` (JSON) | Outbound JSON's `tls.certificate_public_key_sha256` |

All three read from `<server>/certs/<server_name>.crt`. If the cert is missing, the share link silently omits the pin (no error).

See [`./links.md`](./links.md) for share-link generation.

## Package layout

| Package | Responsibility |
| --- | --- |
| `cmd/cheburbox/` | CLI entry point and command logic (Cobra) — `generate`, `validate`, `links`, `rule-set compile`. Coordinates Pass 1 / Pass 2 and writes results. |
| `config/` | Layer 1 schema types, JSON / Jsonnet loading, project discovery, `Validate()`, persisted-credentials extraction. |
| `generate/` | DAG construction, topological sort, two-pass orchestration, builder helpers (Layer 1 → Layer 2), credential generators, cert generator, pin computation, per-server state. |
| `validate/` | Two-phase validation: static cross-server analysis (Phase 1), in-process sing-box check (Phase 2). |
| `links/` | Reads persisted credentials and produces VLESS / Hysteria2 share URIs and JSON outbound stanzas. |
| `ruleset/` | JSON → `.srs` compilation, source discovery, reserved-filename guard. |

## Gotchas

Behavioral quirks worth knowing before debugging.

### CLI surface

- **`--full-reset` replaced an earlier `--clean` flag.** The current source uses `--full-reset` only.
- **`--full-reset` and `--orphan` are mutually exclusive.** Cobra rejects both at parse time.
- **`--full-reset` discards every persisted credential.** UUIDs, passwords, x25519 keypairs, Reality short IDs, obfs passwords — all regenerated. Already-deployed clients will lose access.
- **`--full-reset` also forces cert regeneration**, regardless of SAN match.
- **By default, undeclared users are preserved.** This protects auto-provisioned cross-server users from disappearing on regeneration.
- **`--orphan` keeps only persisted users that are declared in the current `cheburbox.json` or referenced by another server's cross-server outbound.** Stale users from decommissioned proxies are removed.
- **`links --format` accepts `uri` or `json` only.** Any other value errors at parse time.

### Discovery and schema

- **Discovery is single-level.** `Discover` scans only direct child directories of the project root. Nested `cheburbox.json` files at depth > 1 are not picked up.
- **`Discover` skips files at the project root.** A `cheburbox.json` at the top level is ignored; it must reside inside a child directory.
- **Jsonnet wins over JSON.** When both `.cheburbox.jsonnet` and `cheburbox.json` exist in the same directory, Jsonnet takes precedence; the directory is listed once.
- **`version` must be `1`.** Other values are rejected with `unsupported version N (want 1)`. There is no migration mechanism — `CurrentSchemaVersion = 1` is the only accepted value.
- **`version = 0` is rejected before `Validate()`.** `loadFromJSON` errors with `missing or zero version field`.
- **`endpoint` is required when `inbounds` are defined.** Outbound-only (client) servers do not need an endpoint.
- **`dns` section is required.** At least one DNS server must be defined.
- **`listen_port` must be in `[0, 65535]`.** `0` is allowed (used by `tun` inbounds).
- **`users` must be an object array, not a string array.** The form is `[{"name": "alice", "flow": "..."}]`. The original design doc showed strings; the implementation requires objects.

### Generation behavior

- **Two-pass atomic writes.** Every server must succeed in Pass 1 (in memory) before any disk write happens in Pass 2.
- **Topologically leaf-first generation.** Servers with no outbound dependencies are generated first; that's why downstream servers can re-trigger upstream ones via cross-server provisioning.
- **Cycle detection is global.** A cycle reports `(global)` as the affected server in `validate` output.
- **Default user fallback = source server directory name.** A cross-server outbound with empty `user` resolves to the source server's directory name on both sides.
- **Hysteria2 obfs `Type` is hardcoded to `salamander` in cross-server outbound output** when the state has an obfs password, regardless of the original input.
- **VLESS Flow defaults to `xtls-rprx-vision`** when generating a new user. Per-user `Flow` in `cheburbox.json` is honored if specified.
- **Users are sorted alphabetically by name on output.** This makes `config.json` deterministic given persisted credentials.
- **`route.auto_detect_interface = true` is forced when `route` is omitted.** When `route` is specified explicitly, the user's value is preserved as-is; cheburbox does not override it.
- **`experimental.cache_file` is emitted only when `Enabled` is non-nil and `*Enabled == true`.** Pointer semantics distinguish unset from false.
- **Self-signed Ed25519 cert validity = 365 days.** Cheburbox checks regeneration **only by SAN match, not by expiration.** Long-running deployments may keep an expired cert until `--full-reset`.
- **Output files are mode `0644`, directories are `0750`.** A `gosec G306` nolint comment justifies the file mode.
- **Rule-set `.srs` compilation has a disk side-effect during Pass 1.** Failed later steps may leave orphaned `.srs` files even though `config.json` was never written.

### Validation behavior

- **No external `sing-box` binary is required.** Phase 2 links sing-box as a Go library and runs `box.New` + `Close` in-process.
- **Phase 2 chdirs into each server's directory** before parsing, so relative paths like `certs/<name>.crt` resolve. The chdir is deferred-back.
- **Phase 2 is skipped per-server with a Warning if `<server>/config.json` is missing.** Phase 1 still runs; the server reports PASS overall (Warning is not a failure).
- **Hysteria2 server-name collision is a Phase 1 error.** Two `hysteria2` inbounds on the same server with the same `tls.server_name` are rejected (cert files would conflict).
- **`urltest` / `selector` group `outbounds` are intra-server only.** Cross-server outbound tags are not allowed in groups.

### Links behavior

- **`links` requires a prior `generate`.** It reads persisted credentials from `<server>/config.json`. With no prior generate, output is empty (no error).
- **Only `vless` and `hysteria2` inbounds produce links.** Other inbound types (`tun`, etc.) are silently skipped.
- **VLESS UTLS fingerprint differs by context: `firefox` in cross-server generated outbounds, `chrome` in share links.** Two separate fingerprint constants live in `generate/outbound.go` and `links/vless.go`. Both are intentional.
- **Hysteria2 JSON outbound from `links` always sets `tls.alpn = ["h3"]` and `tls.enabled = true`,** ignoring the inbound's ALPN setting.
- **VLESS URI always sets `type=tcp`.** No transport variants are encoded.
- **VLESS URI security mode order:** `reality` (when `RealityInfo` populated) > `tls` (when `ServerName` non-empty) > `none`.
- **Empty VLESS `Flow` is omitted entirely** from both URI and JSON output.
- **Hysteria2 share URI puts the password in the userinfo position:** `hysteria2://<password>@host:port?...`.
- **Reality public key is derived fresh from the persisted private key.** No public key is stored.
- **Only the first persisted Reality `ShortID` ends up in share links** (`sid` query param). Multiple short IDs are reduced to one.
- **VLESS Reality URI's `sni` param comes from `tls.reality.handshake.server`,** not from `tls.server_name`.
- **Hysteria2 `pinSHA256` is omitted silently if the cert file is missing.** No error is emitted.

### Code-style and contributor traps

- **`generate.Generate*` stutter is intentional.** `GenerateConfig`, `GenerateResult`, `GenerateServer`, `GenerateAll` each carry a `//nolint:revive` comment justifying the name as "API clarity."
- **Test helper `func strPtr(s string) *string { return new(s) }` in `config/cheburbox_test.go` looks broken** — Go's builtin `new()` takes a type, not a value. The pattern compiles in current Go but is misleading. **In your own code use `&s` instead;** do not copy this idiom into examples.

## See also

- [`./configuration.md`](./configuration.md) — `cheburbox.json` schema reference
- [`./generate.md`](./generate.md) — generate command, credential lifecycle
- [`./validate.md`](./validate.md) — validation phases and error model
- [`./links.md`](./links.md) — share-link formats and fingerprints
- [`./rule-set.md`](./rule-set.md) — rule-set compilation
