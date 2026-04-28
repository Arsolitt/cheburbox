# Rule-Set Compile

> Compile JSON rule-set sources into the binary `.srs` format that sing-box consumes for routing rules.

## Table of Contents

- [What it does](#what-it-does)
- [Usage](#usage)
- [Flags](#flags)
- [Input sources](#input-sources)
- [Output files](#output-files)
- [When to compile](#when-to-compile)
- [Common errors](#common-errors)

## What it does

`cheburbox rule-set compile` translates a JSON rule-set source into the binary `.srs` format consumed by sing-box at runtime. It uses sing-box's own `srs.Write` encoder, so output is byte-compatible with native sing-box tooling.

The command runs in two modes:

- **single-file mode**: compile one explicit `--input` file to one `--output` path.
- **server mode**: load `<server>/cheburbox.json` (or `.cheburbox.jsonnet`), look at `route.custom_rule_sets`, and compile every matching `<name>.json` source in the server directory into `<server>/rule-set/<name>.srs`.

## Usage

```shell
cheburbox rule-set compile [flags]
```

Compile a single source file:

```shell
cheburbox rule-set compile --input ./extension.json --output ./rule-set/extension.srs
```

Auto-compile every rule-set declared by a server:

```shell
cheburbox rule-set compile --server my-server
```

In server mode, `--input` and `--output` are ignored; targets are derived from `route.custom_rule_sets` in the server's config.

## Flags

| Flag | Type | Default | Purpose |
| --- | --- | --- | --- |
| `--server` | string | `""` | Server directory name. When set, loads that server's config, finds matching `*.json` sources, and compiles each into `<server>/rule-set/<name>.srs`. |
| `--input` | string | `""` | Input JSON rule-set file path. Required (with `--output`) when `--server` is not set. |
| `--output` | string | `""` | Output `.srs` file path. Required (with `--input`) when `--server` is not set. |

## Input sources

The input is a sing-box rule-set JSON document. The `version` field is optional — when omitted, the compiler falls back to sing-box's `constant.RuleSetVersionCurrent`.

Example input:

```json
{
  "version": 4,
  "rules": [
    { "domain_suffix": [".example.com"] },
    { "ip_cidr": ["10.0.0.0/8"] }
  ]
}
```

In server mode, source files are discovered by name: each entry in `route.custom_rule_sets` maps to `<server>/<name>.json`. Files literally named `cheburbox.json` or `config.json` are reserved and never treated as rule-set sources, even if they appear in `custom_rule_sets`. If a listed name has no matching `.json` source, it is silently skipped — no error is emitted.

For how to declare rule-sets in your config, see [`./configuration.md`](./configuration.md). Generated configs reference each compiled rule-set as `{ "type": "local", "path": "rule-set/<name>.srs" }` under `route.rule_set`; sing-box resolves that relative path against its own `config.json` directory at runtime.

## Output files

Output is opaque binary written by sing-box's `srs.Write`. Files land at:

- single-file mode: the path passed to `--output`.
- server mode: `<server>/rule-set/<name>.srs`. The `rule-set/` directory is created with mode `0750` if it does not already exist.

In server mode the command prints `Compiled <name> -> <path>` per file.

> **Note:** Rule-set compilation is **not** an in-memory, atomic operation. The compiler writes the `.srs` file directly to disk via `os.Create` (and, when invoked from `cheburbox generate`, re-reads it back into the managed file list). This happens before the atomic write boundary that protects the rest of generation, so a failure in a later step can leave an orphaned `.srs` file on disk.

## When to compile

Most users do not need to invoke this command directly: `cheburbox generate` already compiles every server's `route.custom_rule_sets` automatically as part of its per-server pipeline (see [`./generate.md`](./generate.md)).

Reach for the standalone command when you want to:

- recompile rule-sets after editing the source JSON without regenerating `config.json`;
- compile a one-off rule-set into a custom path outside the standard `<server>/rule-set/` layout (single-file mode).

## Common errors

| Trigger | Message |
| --- | --- |
| `--server` not set and either `--input` or `--output` empty | `--input and --output are required when --server is not specified` |
| Input file unreadable (missing, no permission) | `read input: <error>` |
| Input is not valid JSON | `parse rule-set JSON: <err>` |
| Output path cannot be created (e.g. parent directory missing, no write permission) | `create output file: <err>` |
