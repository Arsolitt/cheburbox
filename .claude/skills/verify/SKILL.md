---
name: verify
description: Run the canonical pre-handoff check for cheburbox — `golangci-lint run --fix ./...` followed by `go test ./...`. Invoke before reporting a coding task as done, before creating a commit, or whenever the user asks to verify / check / validate the current state of the code.
---

# /verify

Canonical pre-handoff check for cheburbox.

## Steps

1. Run `golangci-lint run --fix ./...` from the repo root.
2. If step 1 modifies files, report which files changed and show the remaining diagnostics (if any). Do NOT proceed to tests while there are lint errors — stop and ask the user how to handle them.
3. If step 1 is clean, run `go test ./...`.
4. Report the outcome:
   - All green: one-line "lint clean, N packages pass".
   - Failures: show the failing package(s) and the first failure of each. Do not paste full test output unless the user asks.

## Notes

- Do not skip step 1. Per `AGENTS.md`: always run `golangci-lint run --fix` first, then fix whatever remains manually.
- Do not run `go build` unless the user asks — `go test ./...` compiles everything test-reachable anyway.
- If the working tree is dirty before verification, mention it in the report so the user is not surprised by lint-fix modifications on top of their own edits.
