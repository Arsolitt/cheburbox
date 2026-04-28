# Quick Start

> Stand up a single sing-box server from scratch — write a minimal `cheburbox.json`, generate the runtime config, validate it in-process, and (optionally) print a share link. End to end in five steps.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Step 1 — Create a project directory](#step-1--create-a-project-directory)
- [Step 2 — Write a minimal `cheburbox.json`](#step-2--write-a-minimal-cheburboxjson)
- [Step 3 — Generate configs](#step-3--generate-configs)
- [Step 4 — Validate the output](#step-4--validate-the-output)
- [Step 5 — Generate share links (optional)](#step-5--generate-share-links-optional)
- [What's next](#whats-next)

## Prerequisites

- The `cheburbox` binary on your `PATH`. See [Installation](./installation.md).
- That's it. Cheburbox links sing-box as a Go library and runs `box.New` in-process during validation, so **no external `sing-box` binary is required** to run `cheburbox validate`.

## Step 1 — Create a project directory

A cheburbox **project** is just a directory whose direct child directories each define one server.

```shell
$ mkdir my-project
$ cd my-project
```

The current working directory is the project root by default. (You can also pass `--project /path/to/root` to any cheburbox command.)

## Step 2 — Write a minimal `cheburbox.json`

Each server lives in its own subdirectory. Create one called `home-server` with a `cheburbox.json` inside:

```shell
$ mkdir home-server
```

Write `home-server/cheburbox.json`:

```json
{
  "version": 1,
  "endpoint": "1.2.3.4",
  "dns": {
    "servers": [
      { "type": "local", "tag": "dns-local" }
    ],
    "final": "dns-local"
  },
  "inbounds": [
    {
      "type": "vless",
      "tag": "vless-in",
      "listen_port": 443,
      "users": [
        { "name": "alice" }
      ]
    }
  ],
  "outbounds": [
    { "type": "direct", "tag": "direct" }
  ]
}
```

What each block does:

- **`version: 1`** — schema version. The current and only supported value is `1`. Omitting it (or setting it to `0`) fails with `missing or zero version field`.
- **`endpoint: "1.2.3.4"`** — public IP or hostname of this server. Required whenever `inbounds` is non-empty (purely-outbound "client" servers may omit it). Replace with your real public address.
- **`dns`** — at least one DNS server is mandatory. Here a single `local` resolver tagged `dns-local` is selected as the default via `final`.
- **`inbounds`** — one VLESS listener on port `443`, with one user named `alice`. **Note**: `users` is an array of **objects** (`[{ "name": "alice" }]`), not strings. Cheburbox auto-generates the UUID for each declared user during `generate` and persists it in the resulting `config.json`.
- **`outbounds`** — one `direct` outbound, used as the default egress for traffic this server proxies.

> **Gotcha — single-level discovery.** Cheburbox only looks at **direct child directories** of the project root. A `cheburbox.json` placed at the root (next to your server folders) is ignored. Likewise, server folders nested two levels deep are not picked up.

## Step 3 — Generate configs

From the project root, run:

```shell
$ cheburbox generate
```

What happens:

1. **Discover.** Cheburbox lists the immediate subdirectories of the current directory and picks the ones containing `cheburbox.json` (or `.cheburbox.jsonnet`).
2. **Resolve & build.** For each server it loads the schema, validates it, and builds a sing-box `option.Options` value in memory. Cross-server outbound references (none in this minimal example) would be sorted into a DAG and processed leaves-first.
3. **Persist credentials.** Cheburbox reads any pre-existing `<server>/config.json` from a previous run and reuses its UUIDs, passwords, and Reality keys so existing clients keep working. On a fresh project there is nothing to read; new credentials are generated.
4. **Two-pass atomic write.** Pass 1 builds every server's output in memory. **Only** if every server succeeds does Pass 2 begin writing files to disk.

For our single-server example the resulting tree is:

```text
my-project/
└── home-server/
    ├── cheburbox.json
    └── config.json
```

That `home-server/config.json` is the file you would feed to a real `sing-box run --config home-server/config.json` on the actual server. It contains the populated VLESS user with a freshly-generated UUID, `xtls-rprx-vision` flow, the DNS section, and the direct outbound.

Other potential outputs (not produced by this minimal example, but worth knowing about):

- `home-server/certs/<server_name>.crt` and `<server_name>.key` — only generated for Hysteria2 inbounds with a `tls.server_name`.
- `home-server/rule-set/<name>.srs` — only generated when `route.custom_rule_sets` lists local rule-set sources.

For the full flag list (`--full-reset`, `--orphan`, `--server`, `--dry-run`), see [Generate](./generate.md).

## Step 4 — Validate the output

```shell
$ cheburbox validate
```

`validate` runs in two phases:

- **Phase 1** — schema and cross-server invariants: required fields, port ranges, cross-server outbound targets resolve, no DAG cycles, no two Hysteria2 inbounds sharing a `tls.server_name` on the same server, urltest/selector member tags exist on the same server.
- **Phase 2** — sing-box parsing: cheburbox calls `box.New` on each `<server>/config.json` in-process. This catches anything sing-box itself would reject at startup (unknown option keys, malformed pass-through `route.rules`, etc.).

> **Tip.** If you run `cheburbox validate` **before** you've ever run `cheburbox generate`, Phase 2 emits a Warning per server (`skipped sing-box check: <server>/config.json not found`) and reports the server as PASS. The warning is informational, not a failure — Phase 1 still runs.

For more detail on each check and how to interpret reports, see [Validate](./validate.md).

## Step 5 — Generate share links (optional)

Once `cheburbox generate` has produced `home-server/config.json`, you can print user share links for VLESS and Hysteria2 inbounds:

```shell
$ cheburbox links --format uri
```

This emits one URI per (server, inbound, user) tuple to stdout. For our example, you'll get a single `vless://...#home-server-vless-in-alice` line.

Other useful flags (full list in [Links](./links.md)):

- `--format json` — emit sing-box-style outbound JSON objects instead of share URIs.
- `--server home-server` — limit output to one server.
- `--user alice` — limit to one user.

> **Gotcha.** `links` reads the **persisted** credentials from `<server>/config.json`. If you haven't run `generate` yet, no credentials exist and `links` produces empty output (no error). Only `vless` and `hysteria2` inbounds produce links; other types (e.g. `tun`) are silently skipped.

## What's next

- [Configuration](./configuration.md) — full schema reference for `cheburbox.json` (every field on every inbound, outbound, DNS, route, Reality, Hysteria2 obfs/masquerade, experimental cache, etc.).
- [Architecture](./architecture.md) — how the two type layers, the cross-server DAG, credential persistence, and the two-pass atomic write fit together.
