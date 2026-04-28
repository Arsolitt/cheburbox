# cheburbox

> A Go CLI that generates and validates `sing-box` configurations across multiple servers from a single declarative schema.

## Table of Contents

- [What it does](#what-it-does)
- [Highlights](#highlights)
- [Quick install](#quick-install)
- [Minimal example](#minimal-example)
- [Documentation](#documentation)
- [Using with AI Assistants](#using-with-ai-assistants)
- [Requirements](#requirements)
- [License](#license)

---

## What it does

Managing `sing-box` configs across multiple servers by hand means juggling UUIDs, passwords, Reality keys,
self-signed certificates, and cross-server references — all of which must stay in sync, otherwise clients lose access.

`cheburbox` turns one declarative `cheburbox.json` (or `.cheburbox.jsonnet`) per server directory into the matching
`config.json` files, persists generated credentials across runs so existing deployments keep working, resolves
cross-server outbound references via a dependency graph, and validates the result with `sing-box`'s own checker
linked as a Go library.

---

## Highlights

- **Declarative schema.** Author one `cheburbox.json` per server; cheburbox produces the corresponding sing-box `config.json`.
- **Cross-server references.** Outbounds can target another server by directory name; cheburbox resolves the target's
  endpoint, inbound, and user via a topologically-sorted DAG with cycle detection.
- **Credentials persist.** UUIDs, passwords, x25519 / Reality keys, and obfs secrets are re-extracted from previously
  generated `config.json` files on each run, so re-running `generate` does not invalidate clients.
- **Atomic two-pass generation.** Pass 1 builds every server entirely in memory; only if all servers succeed does Pass 2
  batch-write files to disk. A single failing server leaves the project untouched.
- **In-process validation.** `cheburbox validate` links the sing-box library directly and runs the same check sing-box
  itself would — no external `sing-box` binary required.
- **Share links for clients.** `cheburbox links` exports VLESS and Hysteria2 connection links in `uri` or `json` form
  from the generated configs.
- **Local rule-set compilation.** `cheburbox rule-set compile` turns JSON rule-set sources into binary `.srs` files,
  either standalone or automatically as part of `generate`.
- **Jsonnet support.** `.cheburbox.jsonnet` is evaluated with a configurable library path (`--jpath`, default `lib`)
  and takes precedence over `cheburbox.json` in the same directory.

---

## Quick install

```shell
$ go install github.com/Arsolitt/cheburbox/cmd/cheburbox@latest
```

Verify the binary is on your `PATH`:

```shell
$ cheburbox --help
```

> **Tip:** To build from a local clone instead, run `go build --output build/cheburbox ./cmd/cheburbox/` from
> the repository root.

---

## Minimal example

Create one directory per server under your project root. The directory name is the server's identifier; the
`cheburbox.json` inside it describes the server.

Project layout:

```text
my-project/
  edge-1/
    cheburbox.json
```

`my-project/edge-1/cheburbox.json`:

```json
{
  "version": 1,
  "endpoint": "1.2.3.4",
  "dns": {
    "servers": [{"type": "local", "tag": "dns-local"}],
    "final": "dns-local"
  },
  "inbounds": [
    {
      "tag": "vless-in",
      "type": "vless",
      "listen_port": 443,
      "users": [{"name": "alice"}]
    }
  ],
  "outbounds": [{"type": "direct", "tag": "direct"}]
}
```

Generate the sing-box configs, then validate them:

```shell
$ cheburbox generate
$ cheburbox validate
```

`generate` writes `my-project/edge-1/config.json` (plus any required certs and rule-sets). `validate` re-checks
the schema, cross-server references, and runs the in-process sing-box check on each generated `config.json`.

> **Note:** `version` MUST be `1` and `endpoint` is required when `inbounds` are defined. Outbound-only (client)
> servers may omit `endpoint`. `dns` requires at least one server.

---

## Documentation

| Page | Topic |
| --- | --- |
| [Installation](./docs/installation.md) | Install methods, supported Go version, dependencies |
| [Quick Start](./docs/quick-start.md) | First server in under a minute |
| [Configuration](./docs/configuration.md) | Full `cheburbox.json` schema reference |
| [Generate](./docs/generate.md) | `cheburbox generate` flags, credential persistence, dry-run |
| [Validate](./docs/validate.md) | Two-phase validation, exit codes, expected output |
| [Links](./docs/links.md) | `cheburbox links` for VLESS and Hysteria2 share URIs / JSON outbounds |
| [Rule-Set](./docs/rule-set.md) | `cheburbox rule-set compile` and `route.custom_rule_sets` |
| [Architecture](./docs/architecture.md) | Pipeline, DAG, two-pass write, persistence model |

For LLM-friendly consumption, the entire documentation is also available as a single concatenated file: [`llms-full.txt`](./llms-full.txt).

---

## Using with AI Assistants

It is recommended to copy the following prompt and send it to an AI assistant — this can significantly improve the quality of generated configurations:

```text
https://github.com/Arsolitt/cheburbox/blob/main/llms-full.txt This link is the full documentation of cheburbox.

【Role Setting】
You are an expert proficient in sing-box proxy configuration and cheburbox project structure.

【Task Requirements】
1. Knowledge Base: Please read and deeply understand the content of this link, and use it as the sole basis for answering questions and writing configurations.
2. No Hallucinations: Absolutely do not fabricate fields that do not exist in the documentation. If the documentation does not mention it, please tell me directly "Documentation does not mention".
3. Default Format: Output JSON by default (unless I explicitly request a different format), and add key comments.
4. Exception Handling: If you cannot access this link, please inform me clearly and prompt me to manually download the documentation and upload it to you.
```

---

## Requirements

- **Go 1.26.1 or newer** to build or `go install`.
- **No external `sing-box` binary required** — `cheburbox validate` links sing-box as a Go library and runs the check
  in-process.

Direct module dependencies (see `go.mod`): `github.com/sagernet/sing-box`, `github.com/sagernet/sing`,
`github.com/google/go-jsonnet`, `github.com/spf13/cobra`, `github.com/gofrs/uuid/v5`.

---

## License

`cheburbox` is released under the GNU General Public License v3.0. See [LICENSE](./LICENSE) for the full text.
