# Generate

> Build sing-box `config.json` files (plus certificates and compiled rule-sets) for every server in a project, from a single declarative `cheburbox.json` schema.

## Table of Contents

- [What generate does](#what-generate-does)
- [Usage](#usage)
- [Flags](#flags)
- [Output files](#output-files)
- [Credential persistence](#credential-persistence)
- [`--full-reset` behavior](#--full-reset-behavior)
- [`--orphan` behavior](#--orphan-behavior)
- [`--dry-run` behavior](#--dry-run-behavior)
- [`--server` flag](#--server-flag)
- [Two-pass atomic generation](#two-pass-atomic-generation)
- [Common errors](#common-errors)

## What generate does

`cheburbox generate` is the workhorse command. From the project root it:

1. **Discovers servers** by scanning direct child directories for `cheburbox.json` (or `.cheburbox.jsonnet`).
2. **Loads every server's schema** into the user-facing `config.*` types.
3. **Builds a dependency graph (DAG)** from cross-server outbound references — each outbound whose `server` field points at another server creates a directed edge.
4. **Topologically sorts** the graph so leaf servers (no outgoing dependencies) are generated first.
5. **Resolves credentials** per server: re-reads previously generated `<server>/config.json` and reuses persisted UUIDs, passwords, x25519 key pairs, Reality short IDs, and obfs passwords. Missing credentials are minted with `crypto/rand`.
6. **Translates** the user-facing schema into sing-box's `option.*` types (registry-aware decoding via `include.Context()`).
7. **Compiles** any `route.custom_rule_sets` JSON sources into binary `.srs` files.
8. **Batch-writes** all generated artifacts to disk — but only after every server has succeeded in memory.

The whole operation is atomic across servers: if anything fails during in-memory generation, no `config.json` is touched. See [Two-pass atomic generation](#two-pass-atomic-generation) and [`./architecture.md`](./architecture.md).

## Usage

```shell
cheburbox generate [flags]
```

The command inherits two persistent flags from the root command:

- `--project <path>` — project root (default: current working directory)
- `--jpath <path>` — Jsonnet library search path (default: `lib`)

## Flags

| Flag | Type | Default | Description |
| --- | --- | --- | --- |
| `--server` | string | `""` | Generate only this server and its transitive dependencies. Other servers' configs are loaded for graph construction but not written. |
| `--dry-run` | bool | `false` | Run the full in-memory generation but emit results as JSON to stdout instead of writing to disk. |
| `--full-reset` | bool | `false` | Discard all persisted credentials and certificates. Regenerate every UUID, password, x25519 key pair, Reality short ID, and obfs password. Remove undeclared users. |
| `--orphan` | bool | `false` | Remove persisted users that are no longer declared in `cheburbox.json` and not referenced by any other server's cross-server outbound. |

> **Note:** `--full-reset` and `--orphan` are **mutually exclusive**. Setting both errors out at command parse time (`cobra.MarkFlagsMutuallyExclusive`).

## Output files

For each server the generator writes:

| Path | Mode | When |
| --- | --- | --- |
| `<project>/<server>/config.json` | `0644` | Always. The rendered sing-box config. |
| `<project>/<server>/certs/<server_name>.crt` | `0644` | When the server has a `hysteria2` inbound. |
| `<project>/<server>/certs/<server_name>.key` | `0644` | When the server has a `hysteria2` inbound. Holds the Ed25519 private key. |
| `<project>/<server>/rule-set/<name>.srs` | `0644` | One per entry in `route.custom_rule_sets` that has a matching `<name>.json` source on disk. |

Output directories are created with mode `0750`. Hysteria2 certificates are self-signed Ed25519 with serial number `1`, valid for 365 days from generation. The CN and DNS SAN both equal `tls.server_name`. The certificate is regenerated when:

- The cert files are missing.
- `--full-reset` is set.
- The parsed cert's DNS SANs no longer contain the current `server_name`.

`CertNeedsRegeneration` does **not** check expiry. Long-lived deployments may keep an expired cert until `--full-reset` is run.

`config.json` content is deterministic across runs: VLESS and Hysteria2 user lists are sorted alphabetically by name.

## Credential persistence

On every run, `generate` re-reads each `<server>/config.json` (if present) using sing-box's context-aware decoder. From the parsed `option.Options` it extracts:

- **VLESS** — each user's UUID and Flow.
- **Hysteria2** — each user's password.
- **Reality** — `private_key` and `short_id` list (only when `reality.enabled`). The public key is derived on demand from the private key (tries std, raw-std, and raw-url base64) — it is **not** stored.
- **Obfs** — password.

For each user declared in `cheburbox.json`:

- If persisted credentials exist for that `(tag, userName)` pair, they are reused **verbatim**.
- Otherwise, fresh credentials are minted: a UUIDv4 for VLESS (with default `Flow = xtls-rprx-vision`), a base64-encoded 24-byte random password for Hysteria2.

Per-user `flow` declared in `cheburbox.json` is honored as written; the `xtls-rprx-vision` default applies only at credential **generation** time.

**Why this matters:** if `generate` re-minted credentials on each run, every existing client (including those auto-provisioned via cross-server outbounds) would lose access on the next regeneration. Persistence is what keeps deployments stable. See [`./architecture.md`](./architecture.md) for the full state model.

By default, persisted users that are **not** declared in the current `cheburbox.json` are **preserved** in the regenerated config. This protects auto-provisioned cross-server users from being deleted accidentally. Use `--orphan` or `--full-reset` to change that behavior.

## `--full-reset` behavior

> **Danger:** `--full-reset` zeroes the persisted credential struct entirely. Every UUID, password, x25519 keypair, Reality short ID, and obfs password is regenerated from scratch. **Existing deployed clients will lose access.** Hysteria2 certificates are also regenerated regardless of SAN match. Run this only when you are intentionally rotating credentials and ready to redistribute new client configs.

Effects:

- Persisted struct replaced with `config.EmptyPersistedCredentials`.
- Every user is re-minted with fresh secrets.
- Every Hysteria2 cert is regenerated (new public key → new pin SHA-256).
- Undeclared persisted users are **not** preserved.
- Mutually exclusive with `--orphan`.

## `--orphan` behavior

`--orphan` cleans up persisted users that have outlived their declarations. After resolving credentials, it keeps only persisted users that satisfy at least one of:

- The user is declared in the current server's `cheburbox.json`.
- The user is referenced by **another** server's cross-server outbound (resolved via `crossServerUserRefs()`, with the source-server-name fallback applied to outbounds that omit the `user` field).

Stale users — for example, leftovers from a decommissioned downstream server — are removed.

Mutually exclusive with `--full-reset`.

## `--dry-run` behavior

`--dry-run` performs the full in-memory pipeline (load → graph → topological sort → credential resolution → conversion to sing-box types → marshal). Instead of writing files, it prints a JSON array to stdout:

```text
[
  {
    "server": "<server-name>",
    "files": [
      {"path": "<relative-path>", "content": "<base64-stdEncoding>"}
    ]
  }
]
```

Two important properties:

- **No disk writes.** No `config.json`, no certs.
- **Side effects from rule-set compilation are still possible.** The `.srs` compile path uses `os.Create` + read-back during Pass 1 (see [Two-pass atomic generation](#two-pass-atomic-generation)). Failed later steps may leave orphaned `.srs` files even in dry-run.

Use `--dry-run` to preview a change before committing to it.

## `--server` flag

`--server <name>` restricts generation to one server **plus its transitive dependencies**. The graph is still built from every discovered server (so cross-server references can be resolved), but only the selected subset is generated and written.

The set of servers generated for `--server X` is computed via `Graph.TransitiveDependencies(X)` — that is, `X` and every server that `X` depends on (directly or transitively). Servers that depend **on** `X` are not included.

## Two-pass atomic generation

Generation runs in two phases:

1. **Pass 1 (in-memory).** Build the DAG, topologically sort, then generate every selected server. Results are accumulated as `[]GenerateResult{Server, []FileOutput{Path, Content}}` in memory. After generating server X, any "dirty" downstream servers — whose users were just provisioned via cross-server outbounds in X — are regenerated.
2. **Pass 2 (batch write).** Only after Pass 1 has succeeded for every server does `writeResults()` walk the result list and write files. If any server failed during Pass 1, **no** files are touched.

One caveat: rule-set compilation writes `.srs` files during Pass 1 (compile uses `os.Create`, then reads the bytes back into the result list). A later Pass 1 failure may therefore leave orphaned `.srs` files on disk. Everything else respects the atomic boundary.

See [`./architecture.md`](./architecture.md) for the full design.

## Common errors

| Message | Cause |
| --- | --- |
| `cycle detected in server dependencies` | Cross-server outbounds form a directed cycle. Break the cycle in `cheburbox.json`. |
| `server X has a self-referencing outbound Y` | Outbound `Y` on server `X` has its `server` field set to `X`. |
| `server X outbound Y references unknown server Z` | Outbound `Y`'s `server` field names a server that is not present under the project root. |
| `derive public key for inbound X: ...` | Persisted Reality private key for inbound `X` cannot be base64-decoded by any of std / raw-std / raw-url. |
| `if any flags in the group [full-reset orphan] are set none of the others can be` | Both `--full-reset` and `--orphan` were specified. Pick one. |
| `unsupported version N (want 1)` | `cheburbox.json` has `version` other than `1`. |
| `missing or zero version field` | `version` is unset or `0`. |
| `endpoint is required when inbounds are defined` | A server with inbounds is missing the top-level `endpoint`. |
| `dns section is required: at least one dns server must be defined` | The `dns` block is missing or empty. |

For schema-level details see [`./configuration.md`](./configuration.md). To verify generated configs against sing-box itself see [`./validate.md`](./validate.md).
