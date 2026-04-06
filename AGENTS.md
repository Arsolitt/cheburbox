# Agent Guidelines for Cheburbox

## Build/Test Commands

- Build: `go build -o build/cheburbox ./cmd/cheburbox/`
- Install: `go install github.com/Arsolitt/cheburbox/cmd/cheburbox@latest`
- Run all tests: `go test ./...`
- Run single test: `go test -run TestFunctionName ./path/to/package`
- Run tests with coverage: `go test -cover ./...`
- Run tests verbosely: `go test -v -run TestFunctionName ./path/to/package`
- Lint code: `golangci-lint run`
- Lint and auto-fix: `golangci-lint run --fix`
- Always run `golangci-lint run --fix` first to auto-resolve issues before fixing remaining ones manually

## Linter Configuration

The project uses golangci-lint v2 with a strict configuration (`.golangci.yaml`).
Key linter settings to be aware of:

- **Line length**: max 120 characters (golines formatter)
- **Import grouping**: stdlib, external, internal — each group separated by blank line (goimports)
- **Complexity limits**: cyclomatic complexity ≤ 30, cognitive complexity ≤ 20, functions ≤ 100 lines / 50 statements
- **Error checking**: all errors must be checked (errcheck), use `fmt.Errorf("context: %w", err)` wrapping
- **No naked returns**: disabled for all function lengths
- **No named returns**: enforced (nonamedreturns)
- **Sentinel errors**: prefix with `Err`, error types suffix with `Error` (errname)
- **No global variables**: avoid them; reassign linter checks all patterns
- **No `math/rand`**: use `math/rand/v2` in non-test files
- **No `log`**: use `log/slog` instead
- **Exhaustive switches**: required for enums (exhaustive)
- **No magic numbers**: use constants (mnd)
- **`//nolint` directives**: must specify linter name and provide explanation (nolintlint)
- **HTTP**: use `context.Context`, close response bodies (bodyclose, noctx)
- **Printf naming**: printf-like functions must end with `f` (goprintffuncname)

## Code Style Guidelines

### Imports
- Order: stdlib, external packages, internal packages (each group separated by blank line)
- Use aliases only when necessary to avoid conflicts
- Handled automatically by goimports formatter

```go
import (
    "fmt"
    "os"

    "github.com/spf13/cobra"

    "github.com/Arsolitt/cheburbox/config"
)
```

### Formatting
- Lines max 120 characters
- Use `gofmt`/`goimports` compatible formatting
- Run `golangci-lint run --fix` to auto-format

### Types & Structs
- Exported fields use CamelCase, unexported fields use camelCase
- Use struct tags only for serialization (JSON, YAML, etc.)
- Group related fields with blank lines between sections
- Don't embed `sync.Mutex` or `sync.RWMutex` — use explicit fields

### Functions
- Exported functions use PascalCase, private functions use camelCase
- Keep functions focused: ≤ 100 lines, ≤ 50 statements
- Keep cyclomatic complexity ≤ 30, cognitive complexity ≤ 20
- Use early returns to reduce nesting
- Return errors, don't panic unless unrecoverable
- No naked returns

### Error Handling
- Wrap errors with `fmt.Errorf("context: %w", err)` to preserve chain
- Check errors immediately after function calls
- Sentinel errors: `var ErrSomething = errors.New("...")`
- Error types: `type SomethingError struct{ ... }` with `func (e SomethingError) Error() string`
- Use `t.Fatalf()` for test setup failures, `t.Errorf()` for assertion failures

### Naming Conventions
- Constants use PascalCase for exported, camelCase for internal
- Test functions follow `TestFunctionName` pattern
- Printf-like functions must end with `f` (e.g., `Infof`, `Errorf`)
- Avoid meaningless package names like `utils`, `common`

### Comments
- Exported symbols must have doc comments
- Package comments describe purpose and responsibilities
- Function comments start with what it does, not how
- Comments must end with a period (godot linter)
- Doc comments use full sentences: `"Does X and returns Y."`

### Testing
- Write tests for all exported functions
- Use table-driven tests for multiple test cases
- Test both success and error paths
- Use `strings.NewReader()` or `bytes.Buffer` for I/O testing
- Use `t.TempDir()` instead of `os.TempDir()` in tests

### Package Organization
- `cmd/cheburbox/`: CLI entry point and command logic (package main)
- `config/`: cheburbox.json schema types, loading, discovery, and validation (exported library package)
- Tests: `*_test.go` alongside implementation files

### Security
- Use `crypto/rand` for cryptographic randomness (not `math/rand`)
- No `math/rand` in non-test files — use `math/rand/v2`
- Use `log/slog` instead of `log`
- Always close HTTP response bodies
- Always pass `context.Context` to HTTP requests

### Dependencies
- Forbidden: `github.com/golang/protobuf` (use `google.golang.org/protobuf`)
- Forbidden: `github.com/satori/go.uuid` (use `github.com/google/uuid`)
- Forbidden: `github.com/gofrs/uuid` (use v5+)
- Check `.golangci.yaml` `depguard` section for full deny list
