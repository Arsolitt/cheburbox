## CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this project is

`cheburbox` is a Go CLI that generates and validates sing-box configs across multiple servers from a declarative `cheburbox.json` schema. It resolves cross-server references (one server referencing another as a client), persists generated credentials (UUIDs, passwords, x25519 keys) by re-reading them from previously generated `config.json` files, and post-validates the output via `sing-box check`. The `ruleset/` package compiles JSON rule-set sources into binary `.srs` files for sing-box.

Entry point: `cmd/cheburbox/`. User-facing schema: `config/`. Generation logic: `generate/`. Output validation: `validate/`. Rule-set compilation: `ruleset/`.

## Files not to touch

- **`BACKLOG.md`** — personal notes. Do not read, edit, or reference it in any output.

## Files with special handling

- **`llms-full.txt`** — LLM-friendly cheburbox documentation in single-file `llms-full.txt` format (~78 KB). Maintain via the `/writing-llms-docs` skill, which delegates parsing and rewriting to subagents. Do not pull the full file into the main context window; let subagents handle it.

## Commands

- Build: `go build --output build/cheburbox ./cmd/cheburbox/`
- All tests: `go test ./...`
- Single test: `go test --run TestFunctionName ./path/to/package`
- Lint + auto-fix (canonical, run this FIRST before any manual fix): `golangci-lint run --fix`
- Full pre-handoff check: use the `/verify` skill (runs lint-fix + full test suite).

## Architecture gotchas

- **Two layers of types.** `config/` structs are the Cheburbox user-facing JSON schema; the final output uses sing-box option structs (which require context-aware unmarshaling). Generation translates the first into the second — do not conflate them.
- **Atomic two-pass generation.** Pass 1 processes everything in memory: build DAG → topological sort → generate. Pass 2 batch-writes only if Pass 1 succeeded. Never write partial output mid-generation.
- **Credentials persist.** Generated UUIDs, passwords, and x25519 keys are extracted from previously generated `config.json` files on each run. Do not regenerate them if they already exist — that breaks existing deployments.

## Code style (enforced by `.golangci.yaml`, golangci-lint v2)

Run `golangci-lint run --fix` first; fix whatever remains manually.

- Imports: stdlib / external / internal groups separated by blank lines (goimports).
- Line length ≤ 120 (golines).
- Functions ≤ 100 lines / ≤ 50 statements, cyclomatic ≤ 30, cognitive ≤ 20.
- Errors: always checked; wrap with `fmt.Errorf("context: %w", err)`.
- Sentinel errors: `Err*` prefix; error types: `*Error` suffix.
- Exported doc comments are full sentences ending with a period (godot).
- **No** naked returns, **no** named returns (nonamedreturns), **no** global variables, **no** magic numbers (mnd).
- **No** `math/rand` in non-test code — use `math/rand/v2`; use `crypto/rand` for anything cryptographic.
- **No** `log` — use `log/slog`.
- Exhaustive switches required for enums (exhaustive).
- `//nolint` directives must name the linter and explain why.
- HTTP: always pass `context.Context`; always close response bodies.
- Printf-like functions end with `f` (goprintffuncname).
- Forbidden deps: `golang/protobuf` → `google.golang.org/protobuf`; `satori/go.uuid` → `google/uuid`; `gofrs/uuid` < v5 → v5+. Full deny list in `.golangci.yaml` `depguard` section.

## Testing

- Write tests for all exported functions; table-driven when multiple cases.
- `t.Fatalf` for setup failures, `t.Errorf` for assertion failures.
- Use `t.TempDir()`, never `os.TempDir()`.
- Cover both success and error paths.

## References

- @AGENTS.md — original agent instructions (kept for cross-tool compatibility; `CLAUDE.md` is the authoritative source).
- `.golangci.yaml` — full linter config and deny list.
- `docs/superpowers/` — phase-by-phase design docs for ongoing refactors.
