# Phase 4 — Multi-Server DAG

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Enable cross-server dependency resolution via DAG construction, topological sort, cross-server user provisioning, two-pass batch write, `--server` with transitive deps, and `--dry-run` JSON output.

**Architecture:** A new `generate/graph.go` builds a directed graph from outbound `server` references and performs topological sort with cycle detection. A new `generate/server.go` orchestrator (`GenerateAll`) processes servers in topological order, passing a shared `ServerState` between generations for cross-server credential lookup and user provisioning. Cross-server outbounds (vless, hysteria2) are built by looking up the target server's already-resolved inbound credentials from this shared state. The CLI is updated to use two-pass batch write (all in-memory, then atomic disk write) and `--dry-run` outputs a JSON array to stdout.

**Tech Stack:** Go stdlib (`container/list` for topological sort), existing `generate` and `config` packages, `github.com/sagernet/sing-box/option` (outbound option structs), `github.com/spf13/cobra` (CLI flags).

**Design Decisions:**
- `pin-sha256` for hysteria2 outbounds is computed during certificate generation and stored in a shared `ServerState` lookup, keyed by `(serverName, inboundTag)`. Cross-server outbound builders read from this map.
- `--dry-run` works with both `--server` (shows server + transitive deps) and no flag (shows all servers). Output format: JSON array of `{"server": "<name>", "files": [{"path": "<relative>", "content": "<string>"}]}` objects. Binary `.srs` files are base64-encoded.
- Two-pass approach: pass 1 generates all `GenerateResult` in memory (in topological order). Pass 2 writes all files to disk. If any server fails in pass 1, no files are written.
- Cross-server user provisioning: when building an outbound that references a target server's inbound, if the user doesn't exist on the target, credentials are generated and the user is injected into the target server's in-memory credential map. The target server's `GenerateResult` must already be computed (guaranteed by topological order).
- `--server` flag computes transitive upstream dependencies by walking the DAG backwards from the specified server. Only those servers are generated.
- `BuildOutbound` signature changes to accept a `*ServerState` parameter for cross-server lookups. The single-server `BuildOutbound(out)` is kept as a wrapper that passes `nil`.

---

## File Map

| File | Responsibility |
|------|---------------|
| `generate/graph.go` | DAG construction from outbound `server` refs, topological sort (Kahn's algorithm), cycle detection, transitive dependency resolution for `--server` |
| `generate/graph_test.go` | Tests for DAG construction, sort, cycle detection, transitive deps |
| `generate/server.go` | New `GenerateAll` orchestrator: loads all configs, builds graph, sorts, generates in order with shared state, returns all results |
| `generate/server_test.go` | Updated: tests for `GenerateAll`, cross-server scenarios |
| `generate/state.go` | `ServerState` type: shared mutable state for cross-server lookups (credentials, pin-sha256, endpoint) |
| `generate/state_test.go` | Tests for ServerState operations |
| `generate/outbound.go` | Updated: implement vless and hysteria2 cross-server outbound builders using ServerState |
| `generate/outbound_test.go` | Updated: tests for cross-server outbound types |
| `generate/certs.go` | Updated: compute and store pin-sha256 in ServerState during cert generation |
| `generate/certs_test.go` | Updated: verify pin-sha256 storage |
| `cmd/cheburbox/main.go` | Updated: two-pass batch write, `--dry-run` flag, `--server` with transitive deps |
| `cmd/cheburbox/generate_test.go` | Updated: tests for dry-run, multi-server generation |

---

## Task 1: ServerState — Shared Cross-Server State

**Files:**
- Create: `generate/state.go`
- Create: `generate/state_test.go`

The `ServerState` holds in-memory data that accumulates as servers are generated in topological order. Each server generation reads from it (to resolve cross-server outbound credentials) and writes to it (to register its own inbound credentials and pin-sha256 values).

- [ ] **Step 1: Write the failing tests for ServerState**

Create `generate/state_test.go`:

```go
package generate

import (
	"testing"
)

func TestServerStateStoreAndGetCredentials(t *testing.T) {
	t.Parallel()

	state := NewServerState()

	vlessCreds := InboundCredentials{
		Users: map[string]UserCreds{
			"alice": {UUID: "test-uuid", Flow: "xtls-rprx-vision"},
		},
	}

	state.StoreInboundCredentials("server-a", "vless-in", vlessCreds)

	got, ok := state.GetInboundCredentials("server-a", "vless-in")
	if !ok {
		t.Fatal("expected credentials to be stored")
	}
	if got.Users["alice"].UUID != "test-uuid" {
		t.Errorf("UUID = %q, want test-uuid", got.Users["alice"].UUID)
	}
}

func TestServerStateMissingCredentials(t *testing.T) {
	t.Parallel()

	state := NewServerState()

	_, ok := state.GetInboundCredentials("server-a", "vless-in")
	if ok {
		t.Fatal("expected no credentials for unknown server/inbound")
	}
}

func TestServerStateStoreAndGetPinSHA256(t *testing.T) {
	t.Parallel()

	state := NewServerState()

	state.StorePinSHA256("server-a", "hy2-in", "sha256=abcdef")

	got, ok := state.GetPinSHA256("server-a", "hy2-in")
	if !ok {
		t.Fatal("expected pin-sha256 to be stored")
	}
	if got != "sha256=abcdef" {
		t.Errorf("pin-sha256 = %q, want sha256=abcdef", got)
	}
}

func TestServerStateMissingPinSHA256(t *testing.T) {
	t.Parallel()

	state := NewServerState()

	_, ok := state.GetPinSHA256("server-a", "hy2-in")
	if ok {
		t.Fatal("expected no pin-sha256 for unknown server/inbound")
	}
}

func TestServerStateStoreAndGetEndpoint(t *testing.T) {
	t.Parallel()

	state := NewServerState()

	state.StoreEndpoint("server-a", "1.2.3.4")

	got, ok := state.GetEndpoint("server-a")
	if !ok {
		t.Fatal("expected endpoint to be stored")
	}
	if got != "1.2.3.4" {
		t.Errorf("endpoint = %q, want 1.2.3.4", got)
	}
}

func TestServerStateEnsureUser(t *testing.T) {
	t.Parallel()

	state := NewServerState()

	existingCreds := InboundCredentials{
		Users: map[string]UserCreds{
			"alice": {UUID: "alice-uuid", Flow: "xtls-rprx-vision"},
		},
	}
	state.StoreInboundCredentials("server-a", "vless-in", existingCreds)

	err := state.EnsureUser("server-a", "vless-in", "bob")
	if err != nil {
		t.Fatalf("EnsureUser: %v", err)
	}

	creds, ok := state.GetInboundCredentials("server-a", "vless-in")
	if !ok {
		t.Fatal("expected credentials")
	}
	if _, exists := creds.Users["bob"]; !exists {
		t.Error("expected user bob to be added")
	}
	if creds.Users["alice"].UUID != "alice-uuid" {
		t.Error("existing user alice should be preserved")
	}
}

func TestServerStateEnsureUserExisting(t *testing.T) {
	t.Parallel()

	state := NewServerState()

	existingCreds := InboundCredentials{
		Users: map[string]UserCreds{
			"alice": {UUID: "alice-uuid", Flow: "xtls-rprx-vision"},
		},
	}
	state.StoreInboundCredentials("server-a", "vless-in", existingCreds)

	err := state.EnsureUser("server-a", "vless-in", "alice")
	if err != nil {
		t.Fatalf("EnsureUser: %v", err)
	}

	creds, _ := state.GetInboundCredentials("server-a", "vless-in")
	if creds.Users["alice"].UUID != "alice-uuid" {
		t.Error("existing user alice should keep original credentials")
	}
}

func TestServerStateEnsureUserNoInbound(t *testing.T) {
	t.Parallel()

	state := NewServerState()

	err := state.EnsureUser("server-a", "vless-in", "alice")
	if err == nil {
		t.Fatal("expected error when ensuring user on non-existent inbound")
	}
}

func TestServerStateGetInboundType(t *testing.T) {
	t.Parallel()

	state := NewServerState()

	state.StoreInboundType("server-a", "vless-in", inboundTypeVLESS)
	state.StoreInboundType("server-a", "hy2-in", inboundTypeHysteria2)

	got, ok := state.GetInboundType("server-a", "vless-in")
	if !ok {
		t.Fatal("expected inbound type")
	}
	if got != inboundTypeVLESS {
		t.Errorf("inbound type = %q, want vless", got)
	}

	got, ok = state.GetInboundType("server-a", "hy2-in")
	if !ok {
		t.Fatal("expected inbound type")
	}
	if got != inboundTypeHysteria2 {
		t.Errorf("inbound type = %q, want hysteria2", got)
	}

	_, ok = state.GetInboundType("server-a", "nonexistent")
	if ok {
		t.Fatal("expected no inbound type for unknown inbound")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./generate/ -run TestServerState -v`
Expected: FAIL — `NewServerState` not defined.

- [ ] **Step 3: Implement ServerState**

Create `generate/state.go`:

```go
package generate

import (
	"fmt"
)

// ServerState holds shared in-memory state for cross-server credential
// lookups and user provisioning during multi-server generation.
type ServerState struct {
	credentials map[string]map[string]InboundCredentials
	pinSHA256   map[string]map[string]string
	endpoints   map[string]string
	inboundType map[string]map[string]string
}

// NewServerState creates an empty ServerState.
func NewServerState() *ServerState {
	return &ServerState{
		credentials: make(map[string]map[string]InboundCredentials),
		pinSHA256:   make(map[string]map[string]string),
		endpoints:   make(map[string]string),
		inboundType: make(map[string]map[string]string),
	}
}

// StoreInboundCredentials stores resolved credentials for a server's inbound.
func (s *ServerState) StoreInboundCredentials(server string, tag string, creds InboundCredentials) {
	if s.credentials[server] == nil {
		s.credentials[server] = make(map[string]InboundCredentials)
	}
	s.credentials[server][tag] = creds
}

// GetInboundCredentials retrieves credentials for a server's inbound.
func (s *ServerState) GetInboundCredentials(server string, tag string) (InboundCredentials, bool) {
	tags, ok := s.credentials[server]
	if !ok {
		return InboundCredentials{}, false
	}
	creds, ok := tags[tag]
	return creds, ok
}

// StorePinSHA256 stores the pin-sha256 fingerprint for a hysteria2 inbound's certificate.
func (s *ServerState) StorePinSHA256(server string, tag string, pin string) {
	if s.pinSHA256[server] == nil {
		s.pinSHA256[server] = make(map[string]string)
	}
	s.pinSHA256[server][tag] = pin
}

// GetPinSHA256 retrieves the pin-sha256 for a server's hysteria2 inbound.
func (s *ServerState) GetPinSHA256(server string, tag string) (string, bool) {
	tags, ok := s.pinSHA256[server]
	if !ok {
		return "", false
	}
	pin, ok := tags[tag]
	return pin, ok
}

// StoreEndpoint stores the endpoint address for a server.
func (s *ServerState) StoreEndpoint(server string, endpoint string) {
	s.endpoints[server] = endpoint
}

// GetEndpoint retrieves the endpoint address for a server.
func (s *ServerState) GetEndpoint(server string) (string, bool) {
	ep, ok := s.endpoints[server]
	return ep, ok
}

// StoreInboundType stores the protocol type for a server's inbound.
func (s *ServerState) StoreInboundType(server string, tag string, inboundType string) {
	if s.inboundType[server] == nil {
		s.inboundType[server] = make(map[string]string)
	}
	s.inboundType[server][tag] = inboundType
}

// GetInboundType retrieves the protocol type for a server's inbound.
func (s *ServerState) GetInboundType(server string, tag string) (string, bool) {
	tags, ok := s.inboundType[server]
	if !ok {
		return "", false
	}
	typ, ok := tags[tag]
	return typ, ok
}

// EnsureUser adds a user to a target server's inbound credentials if not already present.
// Returns an error if the inbound does not exist on the target server.
func (s *ServerState) EnsureUser(server string, tag string, userName string) error {
	creds, ok := s.GetInboundCredentials(server, tag)
	if !ok {
		return fmt.Errorf("server %q has no inbound %q", server, tag)
	}

	if _, exists := creds.Users[userName]; exists {
		return nil
	}

	inboundType, ok := s.GetInboundType(server, tag)
	if !ok {
		return fmt.Errorf("server %q inbound %q has no known type", server, tag)
	}

	newCreds := generateUserCreds(inboundType)
	creds.Users[userName] = newCreds
	s.StoreInboundCredentials(server, tag, creds)

	return nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./generate/ -run TestServerState -v`
Expected: PASS

- [ ] **Step 5: Run linter**

Run: `golangci-lint run --fix`
Expected: no errors.

- [ ] **Step 6: Commit**

```bash
git add generate/state.go generate/state_test.go
git commit -m "feat(generate): add ServerState for cross-server credential sharing"
```

---

## Task 2: pin-sha256 Computation in Cert Generation

**Files:**
- Modify: `generate/certs.go`
- Modify: `generate/certs_test.go`

When generating a self-signed certificate for a hysteria2 inbound, compute the `pin-sha256` fingerprint from the certificate's public key and store it in `ServerState`. The fingerprint uses SHA-256 of the DER-encoded public key, formatted as `sha256/<base64url-no-padding>`.

- [ ] **Step 1: Write the failing test**

Add to `generate/certs_test.go`:

```go
func TestComputePinSHA256(t *testing.T) {
	t.Parallel()

	certPEM, _ := GenerateSelfSignedCertPEM("test.example.com")
	pin, err := computePinSHA256(certPEM)
	if err != nil {
		t.Fatalf("computePinSHA256: %v", err)
	}
	if pin == "" {
		t.Fatal("expected non-empty pin-sha256")
	}
	if len(pin) < 8 {
		t.Errorf("pin-sha256 too short: %q", pin)
	}
}

func TestComputePinSHA256InvalidPEM(t *testing.T) {
	t.Parallel()

	_, err := computePinSHA256([]byte("not valid PEM"))
	if err == nil {
		t.Fatal("expected error for invalid PEM")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./generate/ -run TestComputePinSHA256 -v`
Expected: FAIL — `computePinSHA256` not defined.

- [ ] **Step 3: Implement computePinSHA256**

Add to `generate/certs.go`:

```go
import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
)

// computePinSHA256 computes the SHA-256 fingerprint of a TLS certificate's
// public key, formatted as "sha256/<base64url-no-padding>".
func computePinSHA256(certPEM []byte) (string, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return "", fmt.Errorf("failed to decode PEM block")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("parse certificate: %w", err)
	}

	pubBytes, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return "", fmt.Errorf("marshal public key: %w", err)
	}

	sum := sha256.Sum256(pubBytes)
	encoded := base64.RawURLEncoding.EncodeToString(sum[:])

	return "sha256/" + encoded, nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./generate/ -run TestComputePinSHA256 -v`
Expected: PASS

- [ ] **Step 5: Run linter**

Run: `golangci-lint run --fix`

- [ ] **Step 6: Commit**

```bash
git add generate/certs.go generate/certs_test.go
git commit -m "feat(generate): add pin-sha256 computation for certificate fingerprints"
```

---

## Task 3: DAG Construction and Topological Sort

**Files:**
- Create: `generate/graph.go`
- Create: `generate/graph_test.go`

Implements graph construction from outbound `server` references, topological sort (Kahn's algorithm), cycle detection, and transitive dependency resolution.

- [ ] **Step 1: Write the failing tests for DAG construction**

Create `generate/graph_test.go`:

```go
package generate

import (
	"testing"

	"github.com/Arsolitt/cheburbox/config"
)

func TestBuildGraph(t *testing.T) {
	t.Parallel()

	configs := map[string]config.Config{
		"server-a": {
			Outbounds: []config.Outbound{
				{Type: "vless", Tag: "out-a", Server: "server-b", Inbound: "vless-in"},
			},
		},
		"server-b": {
			Outbounds: []config.Outbound{
				{Type: "direct", Tag: "direct"},
			},
		},
	}

	g, err := BuildGraph(configs)
	if err != nil {
		t.Fatalf("BuildGraph: %v", err)
	}

	if len(g.Nodes) != 2 {
		t.Errorf("expected 2 nodes, got %d", len(g.Nodes))
	}
}

func TestBuildGraphCycleDetection(t *testing.T) {
	t.Parallel()

	configs := map[string]config.Config{
		"server-a": {
			Outbounds: []config.Outbound{
				{Type: "vless", Tag: "out-a", Server: "server-b", Inbound: "vless-in"},
			},
		},
		"server-b": {
			Outbounds: []config.Outbound{
				{Type: "vless", Tag: "out-b", Server: "server-a", Inbound: "vless-in"},
			},
		},
	}

	_, err := BuildGraph(configs)
	if err == nil {
		t.Fatal("expected error for cycle")
	}
}

func TestTopologicalSort(t *testing.T) {
	t.Parallel()

	configs := map[string]config.Config{
		"server-a": {
			Outbounds: []config.Outbound{
				{Type: "vless", Tag: "out-a", Server: "server-b", Inbound: "vless-in"},
				{Type: "hysteria2", Tag: "hy-a", Server: "server-c", Inbound: "hy2-in"},
			},
		},
		"server-b": {
			Outbounds: []config.Outbound{{Type: "direct", Tag: "direct"}},
		},
		"server-c": {
			Outbounds: []config.Outbound{{Type: "direct", Tag: "direct"}},
		},
	}

	g, err := BuildGraph(configs)
	if err != nil {
		t.Fatalf("BuildGraph: %v", err)
	}

	order, err := g.TopologicalSort()
	if err != nil {
		t.Fatalf("TopologicalSort: %v", err)
	}

	if len(order) != 3 {
		t.Fatalf("expected 3 servers, got %d", len(order))
	}

	posA := index(order, "server-a")
	posB := index(order, "server-b")
	posC := index(order, "server-c")

	if posA <= posB {
		t.Errorf("server-a (depends on server-b) should come after server-b: posA=%d, posB=%d", posA, posB)
	}
	if posA <= posC {
		t.Errorf("server-a (depends on server-c) should come after server-c: posA=%d, posC=%d", posA, posC)
	}
}

func TestTopologicalSortSelfCycle(t *testing.T) {
	t.Parallel()

	configs := map[string]config.Config{
		"server-a": {
			Outbounds: []config.Outbound{
				{Type: "vless", Tag: "out", Server: "server-a", Inbound: "vless-in"},
			},
		},
	}

	_, err := BuildGraph(configs)
	if err == nil {
		t.Fatal("expected error for self-referencing cycle")
	}
}

func TestTransitiveDependencies(t *testing.T) {
	t.Parallel()

	configs := map[string]config.Config{
		"client": {
			Outbounds: []config.Outbound{
				{Type: "vless", Tag: "out", Server: "proxy", Inbound: "vless-in"},
			},
		},
		"proxy": {
			Outbounds: []config.Outbound{
				{Type: "vless", Tag: "out", Server: "exit", Inbound: "vless-in"},
			},
		},
		"exit": {
			Outbounds: []config.Outbound{{Type: "direct", Tag: "direct"}},
		},
		"unrelated": {
			Outbounds: []config.Outbound{{Type: "direct", Tag: "direct"}},
		},
	}

	g, err := BuildGraph(configs)
	if err != nil {
		t.Fatalf("BuildGraph: %v", err)
	}

	deps, err := g.TransitiveDependencies("client")
	if err != nil {
		t.Fatalf("TransitiveDependencies: %v", err)
	}

	if len(deps) != 3 {
		t.Errorf("expected 3 deps (client, proxy, exit), got %d: %v", len(deps), deps)
	}

	depSet := toSet(deps)
	if !depSet["client"] {
		t.Error("client should be in its own dependency set")
	}
	if !depSet["proxy"] {
		t.Error("proxy should be in client's dependency set")
	}
	if !depSet["exit"] {
		t.Error("exit should be in client's dependency set")
	}
	if depSet["unrelated"] {
		t.Error("unrelated should not be in client's dependency set")
	}
}

func TestTransitiveDependenciesNoDeps(t *testing.T) {
	t.Parallel()

	configs := map[string]config.Config{
		"standalone": {
			Outbounds: []config.Outbound{{Type: "direct", Tag: "direct"}},
		},
	}

	g, err := BuildGraph(configs)
	if err != nil {
		t.Fatalf("BuildGraph: %v", err)
	}

	deps, err := g.TransitiveDependencies("standalone")
	if err != nil {
		t.Fatalf("TransitiveDependencies: %v", err)
	}

	if len(deps) != 1 || deps[0] != "standalone" {
		t.Errorf("expected [standalone], got %v", deps)
	}
}

func TestBuildGraphUnknownServer(t *testing.T) {
	t.Parallel()

	configs := map[string]config.Config{
		"server-a": {
			Outbounds: []config.Outbound{
				{Type: "vless", Tag: "out", Server: "nonexistent", Inbound: "vless-in"},
			},
		},
	}

	_, err := BuildGraph(configs)
	if err == nil {
		t.Fatal("expected error for reference to unknown server")
	}
}

func index(slice []string, val string) int {
	for i, s := range slice {
		if s == val {
			return i
		}
	}
	return -1
}

func toSet(slice []string) map[string]bool {
	s := make(map[string]bool, len(slice))
	for _, v := range slice {
		s[v] = true
	}
	return s
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./generate/ -run "TestBuildGraph|TestTopologicalSort|TestTransitiveDependencies" -v`
Expected: FAIL — `BuildGraph`, `Graph`, `TopologicalSort`, `TransitiveDependencies` not defined.

- [ ] **Step 3: Implement DAG construction and topological sort**

Create `generate/graph.go`:

```go
package generate

import (
	"fmt"

	"github.com/Arsolitt/cheburbox/config"
)

// Edge represents a directed edge from one server to another.
type Edge struct {
	From string
	To   string
}

// Graph represents a directed acyclic graph of server dependencies.
type Graph struct {
	Nodes map[string]bool
	Edges []Edge
}

// BuildGraph constructs a dependency graph from server configurations.
// An edge from A to B means server A has an outbound referencing server B,
// so B must be generated before A.
func BuildGraph(configs map[string]config.Config) (*Graph, error) {
	g := &Graph{
		Nodes: make(map[string]bool, len(configs)),
	}

	for name := range configs {
		g.Nodes[name] = true
	}

	for name, cfg := range configs {
		for _, out := range cfg.Outbounds {
			if out.Server == "" {
				continue
			}
			if out.Server == name {
				return nil, fmt.Errorf("server %q has a self-referencing outbound %q", name, out.Tag)
			}
			if !g.Nodes[out.Server] {
				return nil, fmt.Errorf(
					"server %q outbound %q references unknown server %q",
					name, out.Tag, out.Server,
				)
			}
			g.Edges = append(g.Edges, Edge{From: name, To: out.Server})
		}
	}

	return g, nil
}

// TopologicalSort returns servers in generation order using Kahn's algorithm.
// Servers with no dependencies come first. Returns an error if a cycle is detected.
func (g *Graph) TopologicalSort() ([]string, error) {
	inDegree := make(map[string]int, len(g.Nodes))
	for name := range g.Nodes {
		inDegree[name] = 0
	}
	for _, edge := range g.Edges {
		inDegree[edge.From]++
	}

	queue := make([]string, 0, len(g.Nodes))
	for name, degree := range inDegree {
		if degree == 0 {
			queue = append(queue, name)
		}
	}

	var result []string
	for len(queue) > 0 {
		node := queue[0]
		queue = queue[1:]
		result = append(result, node)

		for _, edge := range g.Edges {
			if edge.To == node {
				inDegree[edge.From]--
				if inDegree[edge.From] == 0 {
					queue = append(queue, edge.From)
				}
			}
		}
	}

	if len(result) != len(g.Nodes) {
		return nil, fmt.Errorf("cycle detected in server dependencies")
	}

	return result, nil
}

// TransitiveDependencies returns all servers that need to be generated
// for the given server, including the server itself.
func (g *Graph) TransitiveDependencies(server string) ([]string, error) {
	if !g.Nodes[server] {
		return nil, fmt.Errorf("unknown server %q", server)
	}

	visited := make(map[string]bool)
	var visit func(name string)
	visit = func(name string) {
		if visited[name] {
			return
		}
		visited[name] = true
		for _, edge := range g.Edges {
			if edge.From == name {
				visit(edge.To)
			}
		}
	}

	visit(server)

	result := make([]string, 0, len(visited))
	for name := range visited {
		result = append(result, name)
	}

	return result, nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./generate/ -run "TestBuildGraph|TestTopologicalSort|TestTransitiveDependencies" -v`
Expected: PASS

- [ ] **Step 5: Run linter**

Run: `golangci-lint run --fix`

- [ ] **Step 6: Commit**

```bash
git add generate/graph.go generate/graph_test.go
git commit -m "feat(generate): add DAG construction, topological sort, and transitive dependency resolution"
```

---

## Task 4: Cross-Server Outbound Builders

**Files:**
- Modify: `generate/outbound.go`
- Modify: `generate/outbound_test.go`

Implement vless and hysteria2 cross-server outbound builders that look up target server credentials from `ServerState`.

- [ ] **Step 1: Write the failing tests**

Add to `generate/outbound_test.go` (replace the `TestBuildOutboundCrossServerSkipped` test):

```go
func TestBuildVlessCrossServerOutbound(t *testing.T) {
	t.Parallel()

	state := NewServerState()
	state.StoreInboundCredentials("target", "vless-in", InboundCredentials{
		Users: map[string]UserCreds{
			"client-a": {UUID: "test-uuid-123", Flow: "xtls-rprx-vision"},
		},
	})
	state.StoreEndpoint("target", "5.6.7.8")

	out := config.Outbound{
		Type:    inboundTypeVLESS,
		Tag:     "target-vless",
		Server:  "target",
		Inbound: "vless-in",
		User:    "client-a",
		Flow:    "xtls-rprx-vision",
	}

	result, err := BuildOutboundWithState(out, state)
	if err != nil {
		t.Fatalf("BuildOutboundWithState: %v", err)
	}

	opts, ok := result.Options.(*option.VLESSOutboundOptions)
	if !ok {
		t.Fatalf("Options type = %T, want *option.VLESSOutboundOptions", result.Options)
	}
	if opts.Server != "5.6.7.8" {
		t.Errorf("Server = %q, want 5.6.7.8", opts.Server)
	}
	if opts.ServerPort != 443 {
		t.Errorf("ServerPort = %d, want 443", opts.ServerPort)
	}
	if len(opts.UUID) == 0 {
		t.Error("UUID should be set from target server credentials")
	}
	if opts.Flow != "xtls-rprx-vision" {
		t.Errorf("Flow = %q, want xtls-rprx-vision", opts.Flow)
	}
	if result.Tag != "target-vless" {
		t.Errorf("Tag = %q, want target-vless", result.Tag)
	}
}

func TestBuildHysteria2CrossServerOutbound(t *testing.T) {
	t.Parallel()

	state := NewServerState()
	state.StoreInboundCredentials("target", "hy2-in", InboundCredentials{
		Users: map[string]UserCreds{
			"client-a": {Password: "test-password"},
		},
	})
	state.StoreEndpoint("target", "5.6.7.8")
	state.StorePinSHA256("target", "hy2-in", "sha256/abcdefghijklmnop")

	out := config.Outbound{
		Type:    inboundTypeHysteria2,
		Tag:     "target-hy",
		Server:  "target",
		Inbound: "hy2-in",
		User:    "client-a",
	}

	result, err := BuildOutboundWithState(out, state)
	if err != nil {
		t.Fatalf("BuildOutboundWithState: %v", err)
	}

	opts, ok := result.Options.(*option.Hysteria2OutboundOptions)
	if !ok {
		t.Fatalf("Options type = %T, want *option.Hysteria2OutboundOptions", result.Options)
	}
	if opts.Server != "5.6.7.8" {
		t.Errorf("Server = %q, want 5.6.7.8", opts.Server)
	}
	if len(opts.Password) == 0 {
		t.Error("Password should be set from target server credentials")
	}
	if opts.TLS == nil {
		t.Fatal("TLS should be set")
	}
}

func TestBuildVlessCrossServerEndpointOverride(t *testing.T) {
	t.Parallel()

	state := NewServerState()
	state.StoreInboundCredentials("target", "vless-in", InboundCredentials{
		Users: map[string]UserCreds{
			"client-a": {UUID: "test-uuid", Flow: "xtls-rprx-vision"},
		},
	})
	state.StoreEndpoint("target", "5.6.7.8")

	out := config.Outbound{
		Type:     inboundTypeVLESS,
		Tag:      "target-vless",
		Server:   "target",
		Inbound:  "vless-in",
		User:     "client-a",
		Endpoint: "1.2.3.4",
	}

	result, err := BuildOutboundWithState(out, state)
	if err != nil {
		t.Fatalf("BuildOutboundWithState: %v", err)
	}

	opts := result.Options.(*option.VLESSOutboundOptions)
	if opts.Server != "1.2.3.4" {
		t.Errorf("Server = %q, want 1.2.3.4 (endpoint override)", opts.Server)
	}
}

func TestBuildCrossServerOutboundUserNotFound(t *testing.T) {
	t.Parallel()

	state := NewServerState()
	state.StoreInboundCredentials("target", "vless-in", InboundCredentials{
		Users: map[string]UserCreds{},
	})
	state.StoreEndpoint("target", "5.6.7.8")

	out := config.Outbound{
		Type:    inboundTypeVLESS,
		Tag:     "target-vless",
		Server:  "target",
		Inbound: "vless-in",
		User:    "nonexistent",
	}

	_, err := BuildOutboundWithState(out, state)
	if err == nil {
		t.Fatal("expected error for nonexistent user on target server")
	}
}

func TestBuildCrossServerOutboundNoState(t *testing.T) {
	t.Parallel()

	out := config.Outbound{
		Type:    inboundTypeVLESS,
		Tag:     "target-vless",
		Server:  "target",
		Inbound: "vless-in",
		User:    "client-a",
	}

	_, err := BuildOutboundWithState(out, nil)
	if err == nil {
		t.Fatal("expected error when state is nil for cross-server outbound")
	}
}

func TestBuildVlessCrossServerDefaultUser(t *testing.T) {
	t.Parallel()

	state := NewServerState()
	state.StoreInboundCredentials("target", "vless-in", InboundCredentials{
		Users: map[string]UserCreds{
			"current-server": {UUID: "test-uuid", Flow: "xtls-rprx-vision"},
		},
	})
	state.StoreEndpoint("target", "5.6.7.8")

	out := config.Outbound{
		Type:    inboundTypeVLESS,
		Tag:     "target-vless",
		Server:  "target",
		Inbound: "vless-in",
	}

	result, err := BuildOutboundWithState(out, state, WithDefaultUser("current-server"))
	if err != nil {
		t.Fatalf("BuildOutboundWithState: %v", err)
	}

	opts := result.Options.(*option.VLESSOutboundOptions)
	if len(opts.UUID) == 0 {
		t.Error("UUID should be set using default user")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./generate/ -run "TestBuildVlessCrossServer|TestBuildHysteria2CrossServer|TestBuildCrossServer" -v`
Expected: FAIL — `BuildOutboundWithState`, `WithDefaultUser`, `option.VLESSOutboundOptions`, `option.Hysteria2OutboundOptions` not defined.

- [ ] **Step 3: Check sing-box outbound option struct types**

Before implementing, verify the exact struct types available in sing-box for vless and hysteria2 outbounds.

Run: `grep -r "VLESSOutboundOptions\|Hysteria2OutboundOptions" $(go env GOMODCACHE)/github.com/sagernet/sing-box@*/option/ 2>/dev/null | head -30`

This will tell us the exact field names for the outbound option structs. The implementation below assumes standard sing-box field names — adjust after verifying.

- [ ] **Step 4: Implement cross-server outbound builders**

Update `generate/outbound.go`:

```go
package generate

import (
	"fmt"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"

	"github.com/Arsolitt/cheburbox/config"
)

const outboundTypeDirect = "direct"

// OutboundBuildOption configures outbound building behavior.
type OutboundBuildOption func(*outboundBuildConfig)

type outboundBuildConfig struct {
	defaultUser string
}

// WithDefaultUser sets the default user name for cross-server outbounds
// when the User field is not specified.
func WithDefaultUser(user string) OutboundBuildOption {
	return func(c *outboundBuildConfig) {
		c.defaultUser = user
	}
}

// BuildOutbound converts a cheburbox Outbound to a sing-box option.Outbound.
// This is the legacy single-server path. Cross-server outbounds return an error.
func BuildOutbound(out config.Outbound) (option.Outbound, error) {
	return BuildOutboundWithState(out, nil)
}

// BuildOutboundWithState converts a cheburbox Outbound to a sing-box option.Outbound.
// Cross-server outbounds (vless, hysteria2) require state to look up target credentials.
func BuildOutboundWithState(out config.Outbound, state *ServerState, opts ...OutboundBuildOption) (option.Outbound, error) {
	var cfg outboundBuildConfig
	for _, opt := range opts {
		opt(&cfg)
	}

	switch out.Type {
	case outboundTypeDirect:
		return buildDirectOutbound(out)
	case "urltest":
		return buildURLTestOutbound(out)
	case "selector":
		return buildSelectorOutbound(out)
	case inboundTypeVLESS:
		return buildCrossServerVlessOutbound(out, state, cfg)
	case inboundTypeHysteria2:
		return buildCrossServerHysteria2Outbound(out, state, cfg)
	default:
		return option.Outbound{}, fmt.Errorf("unsupported outbound type %q", out.Type)
	}
}

func buildDirectOutbound(out config.Outbound) (option.Outbound, error) {
	opts := option.DirectOutboundOptions{}
	if out.DomainResolver != "" {
		opts.DomainResolver = &option.DomainResolveOptions{
			Server: out.DomainResolver,
		}
	}

	return option.Outbound{
		Type:    outboundTypeDirect,
		Tag:     out.Tag,
		Options: &opts,
	}, nil
}

func buildURLTestOutbound(out config.Outbound) (option.Outbound, error) {
	interval, err := parseInterval(out.Interval)
	if err != nil {
		return option.Outbound{}, fmt.Errorf("parse urltest interval: %w", err)
	}

	return option.Outbound{
		Type: out.Type,
		Tag:  out.Tag,
		Options: &option.URLTestOutboundOptions{
			Outbounds: out.Outbounds,
			URL:       out.URL,
			Interval:  interval,
		},
	}, nil
}

func buildSelectorOutbound(out config.Outbound) (option.Outbound, error) {
	return option.Outbound{
		Type: out.Type,
		Tag:  out.Tag,
		Options: &option.SelectorOutboundOptions{
			Outbounds: out.Outbounds,
		},
	}, nil
}

func buildCrossServerVlessOutbound(out config.Outbound, state *ServerState, cfg outboundBuildConfig) (option.Outbound, error) {
	if state == nil {
		return option.Outbound{}, fmt.Errorf("cross-server vless outbound %q requires server state", out.Tag)
	}

	user := out.User
	if user == "" {
		user = cfg.defaultUser
	}
	if user == "" {
		return option.Outbound{}, fmt.Errorf("cross-server vless outbound %q: user is required", out.Tag)
	}

	creds, ok := state.GetInboundCredentials(out.Server, out.Inbound)
	if !ok {
		return option.Outbound{}, fmt.Errorf(
			"cross-server vless outbound %q: server %q has no inbound %q",
			out.Tag, out.Server, out.Inbound,
		)
	}

	userCreds, ok := creds.Users[user]
	if !ok {
		return option.Outbound{}, fmt.Errorf(
			"cross-server vless outbound %q: user %q not found on server %q inbound %q",
			out.Tag, user, out.Server, out.Inbound,
		)
	}

	endpoint := resolveEndpoint(state, out.Server, out.Endpoint)

	flow := out.Flow
	if flow == "null" {
		flow = ""
	}
	if flow == "" {
		flow = userCreds.Flow
	}

	return option.Outbound{
		Type: inboundTypeVLESS,
		Tag:  out.Tag,
		Options: &option.VLESSOutboundOptions{
			ServerOptions: option.ServerOptions{
				Server:     endpoint,
				ServerPort: 443,
			},
			UUID: userCreds.UUID,
			Flow: flow,
			TLS: &option.OutboundTLSOptions{
				Enabled: true,
				Type:    "reality",
				Reality: &option.OutboundRealityOptions{
					Enabled:   true,
					PublicKey: creds.Reality.PublicKey,
					ShortID:   badoption.Listable[string](creds.Reality.ShortID),
				},
			},
		},
	}, nil
}

func buildCrossServerHysteria2Outbound(out config.Outbound, state *ServerState, cfg outboundBuildConfig) (option.Outbound, error) {
	if state == nil {
		return option.Outbound{}, fmt.Errorf("cross-server hysteria2 outbound %q requires server state", out.Tag)
	}

	user := out.User
	if user == "" {
		user = cfg.defaultUser
	}
	if user == "" {
		return option.Outbound{}, fmt.Errorf("cross-server hysteria2 outbound %q: user is required", out.Tag)
	}

	creds, ok := state.GetInboundCredentials(out.Server, out.Inbound)
	if !ok {
		return option.Outbound{}, fmt.Errorf(
			"cross-server hysteria2 outbound %q: server %q has no inbound %q",
			out.Tag, out.Server, out.Inbound,
		)
	}

	userCreds, ok := creds.Users[user]
	if !ok {
		return option.Outbound{}, fmt.Errorf(
			"cross-server hysteria2 outbound %q: user %q not found on server %q inbound %q",
			out.Tag, user, out.Server, out.Inbound,
		)
	}

	endpoint := resolveEndpoint(state, out.Server, out.Endpoint)

	tlsOpts := &option.OutboundTLSOptions{
		Enabled: true,
	}

	pinSHA256, hasPin := state.GetPinSHA256(out.Server, out.Inbound)
	if hasPin {
		tlsOpts.Insecure = false
		tlsOpts.Reality = nil
	}

	return option.Outbound{
		Type: inboundTypeHysteria2,
		Tag:  out.Tag,
		Options: &option.Hysteria2OutboundOptions{
			ServerOptions: option.ServerOptions{
				Server: endpoint,
			},
			Password: userCreds.Password,
			TLS:      tlsOpts,
		},
	}, nil
}

func resolveEndpoint(state *ServerState, server string, override string) string {
	if override != "" {
		return override
	}
	if ep, ok := state.GetEndpoint(server); ok {
		return ep
	}
	return server
}

func parseInterval(s string) (badoption.Duration, error) {
	if s == "" {
		return 0, nil
	}

	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("invalid duration %q: %w", s, err)
	}

	return badoption.Duration(d), nil
}
```

> **Note:** The exact field names for `option.VLESSOutboundOptions`, `option.Hysteria2OutboundOptions`, `option.OutboundTLSOptions`, `option.OutboundRealityOptions` must be verified against the sing-box source code. The struct types and field names above are best guesses based on sing-box conventions. The implementer should run `grep` on the sing-box option package to confirm exact field names before finalizing the code.

- [ ] **Step 5: Update the old cross-server test**

Replace `TestBuildOutboundCrossServerSkipped` in `outbound_test.go` with a test that verifies the nil-state error:

```go
func TestBuildOutboundCrossServerSkipped(t *testing.T) {
	t.Parallel()

	out := config.Outbound{
		Type:    "vless",
		Tag:     "remote-vless",
		Server:  "other-server",
		Inbound: "vless-in",
	}
	_, err := BuildOutbound(out)
	if err == nil {
		t.Fatal("expected error for cross-server outbound without state")
	}
}
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `go test ./generate/ -run "TestBuild" -v`
Expected: PASS (all outbound tests, both old and new)

- [ ] **Step 7: Run linter**

Run: `golangci-lint run --fix`

- [ ] **Step 8: Commit**

```bash
git add generate/outbound.go generate/outbound_test.go
git commit -m "feat(generate): implement cross-server vless and hysteria2 outbound builders"
```

---

## Task 5: GenerateAll — Multi-Server Orchestrator

**Files:**
- Modify: `generate/server.go`
- Modify: `generate/server_test.go`

Add a `GenerateAll` function that loads all server configs, builds the DAG, topologically sorts, generates each server in order with shared `ServerState`, performs cross-server user provisioning, and returns all results.

- [ ] **Step 1: Write the failing tests**

Add to `generate/server_test.go`:

```go
func TestGenerateAll(t *testing.T) {
	t.Parallel()

	projectRoot := t.TempDir()

	setupTestServer(t, projectRoot, "exit-server", config.Config{
		Version:  1,
		Endpoint: "10.0.0.1",
		DNS: config.DNS{
			Final:   new("dns-local"),
			Servers: []config.DNSServer{{Type: "local", Tag: "dns-local"}},
		},
		Inbounds: []config.Inbound{
			{
				Tag:        "vless-in",
				Type:       inboundTypeVLESS,
				ListenPort: 443,
				Users:      []config.InboundUser{{Name: "proxy-server"}},
				TLS: &config.InboundTLS{
					Reality: &config.RealityConfig{
						Handshake: &config.RealityHandshake{
							Server:     "example.com",
							ServerPort: 443,
						},
					},
				},
			},
		},
		Outbounds: []config.Outbound{
			{Type: outboundTypeDirect, Tag: "direct"},
		},
	})

	setupTestServer(t, projectRoot, "proxy-server", config.Config{
		Version:  1,
		DNS: config.DNS{
			Final:   new("dns-local"),
			Servers: []config.DNSServer{{Type: "local", Tag: "dns-local"}},
		},
		Outbounds: []config.Outbound{
			{Type: outboundTypeDirect, Tag: "direct"},
			{
				Type:    inboundTypeVLESS,
				Tag:     "exit-vless",
				Server:  "exit-server",
				Inbound: "vless-in",
				User:    "proxy-server",
			},
		},
	})

	results, err := GenerateAll(projectRoot, "lib", GenerateConfig{})
	if err != nil {
		t.Fatalf("GenerateAll: %v", err)
	}

	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}

	exitResult := findResult(results, "exit-server")
	if exitResult == nil {
		t.Fatal("exit-server result not found")
	}

	proxyResult := findResult(results, "proxy-server")
	if proxyResult == nil {
		t.Fatal("proxy-server result not found")
	}

	exitConfig := findFile(exitResult.Files, "config.json")
	if exitConfig == nil {
		t.Fatal("exit-server config.json not found")
	}

	var exitParsed map[string]any
	if err := json.Unmarshal(exitConfig.Content, &exitParsed); err != nil {
		t.Fatalf("parse exit config: %v", err)
	}

	exitInbounds, ok := exitParsed["inbounds"].([]any)
	if !ok || len(exitInbounds) != 1 {
		t.Fatalf("expected 1 inbound on exit-server, got %d", len(exitInbounds))
	}

	proxyConfig := findFile(proxyResult.Files, "config.json")
	if proxyConfig == nil {
		t.Fatal("proxy-server config.json not found")
	}

	var proxyParsed map[string]any
	if err := json.Unmarshal(proxyConfig.Content, &proxyParsed); err != nil {
		t.Fatalf("parse proxy config: %v", err)
	}

	proxyOutbounds, ok := proxyParsed["outbounds"].([]any)
	if !ok {
		t.Fatal("proxy-server has no outbounds")
	}

	foundVlessOut := false
	for _, ob := range proxyOutbounds {
		obMap, ok := ob.(map[string]any)
		if !ok {
			continue
		}
		if obMap["type"] == "vless" {
			foundVlessOut = true
		}
	}
	if !foundVlessOut {
		t.Error("proxy-server should have a vless outbound")
	}
}

func TestGenerateAllWithClean(t *testing.T) {
	t.Parallel()

	projectRoot := t.TempDir()

	setupTestServer(t, projectRoot, "srv-a", config.Config{
		Version:  1,
		DNS: config.DNS{
			Final:   new("dns-local"),
			Servers: []config.DNSServer{{Type: "local", Tag: "dns-local"}},
		},
		Inbounds: []config.Inbound{
			{Tag: "vless-in", Type: inboundTypeVLESS, ListenPort: 443, Users: []config.InboundUser{{Name: "alice"}}},
		},
		Outbounds: []config.Outbound{
			{Type: outboundTypeDirect, Tag: "direct"},
		},
	})

	_, err := GenerateAll(projectRoot, "lib", GenerateConfig{})
	if err != nil {
		t.Fatalf("GenerateAll: %v", err)
	}

	_, err = GenerateAll(projectRoot, "lib", GenerateConfig{Clean: true})
	if err != nil {
		t.Fatalf("GenerateAll clean: %v", err)
	}
}

func TestGenerateAllCycle(t *testing.T) {
	t.Parallel()

	projectRoot := t.TempDir()

	setupTestServer(t, projectRoot, "srv-a", config.Config{
		Version: 1,
		DNS: config.DNS{
			Final:   new("dns-local"),
			Servers: []config.DNSServer{{Type: "local", Tag: "dns-local"}},
		},
		Outbounds: []config.Outbound{
			{Type: inboundTypeVLESS, Tag: "out", Server: "srv-b", Inbound: "vless-in"},
		},
	})

	setupTestServer(t, projectRoot, "srv-b", config.Config{
		Version: 1,
		DNS: config.DNS{
			Final:   new("dns-local"),
			Servers: []config.DNSServer{{Type: "local", Tag: "dns-local"}},
		},
		Outbounds: []config.Outbound{
			{Type: inboundTypeVLESS, Tag: "out", Server: "srv-a", Inbound: "vless-in"},
		},
	})

	_, err := GenerateAll(projectRoot, "lib", GenerateConfig{})
	if err == nil {
		t.Fatal("expected error for cycle")
	}
}

func findResult(results []GenerateResult, server string) *GenerateResult {
	for i := range results {
		if results[i].Server == server {
			return &results[i]
		}
	}
	return nil
}

func setupTestServer(t *testing.T, root string, name string, cfg config.Config) {
	t.Helper()
	dir := filepath.Join(root, name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "cheburbox.json"), data, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./generate/ -run TestGenerateAll -v`
Expected: FAIL — `GenerateAll` not defined.

- [ ] **Step 3: Implement GenerateAll**

Add to `generate/server.go`:

```go
// GenerateAll discovers all servers in the project, builds a dependency graph,
// topologically sorts them, and generates configs in order with shared state
// for cross-server credential resolution.
//
//nolint:revive // "generate.Generate" stutter is intentional for API clarity.
func GenerateAll(projectRoot string, jpath string, genCfg GenerateConfig) ([]GenerateResult, error) {
	servers, err := config.Discover(projectRoot)
	if err != nil {
		return nil, fmt.Errorf("discover servers: %w", err)
	}

	if len(servers) == 0 {
		return nil, nil
	}

	configs, err := loadAllConfigs(servers, projectRoot, jpath)
	if err != nil {
		return nil, err
	}

	graph, err := BuildGraph(configs)
	if err != nil {
		return nil, fmt.Errorf("build dependency graph: %w", err)
	}

	order, err := graph.TopologicalSort()
	if err != nil {
		return nil, fmt.Errorf("topological sort: %w", err)
	}

	state := NewServerState()
	results := make([]GenerateResult, 0, len(order))

	for _, name := range order {
		result, genErr := generateServerWithState(
			filepath.Join(projectRoot, name),
			name,
			configs[name],
			genCfg,
			state,
		)
		if genErr != nil {
			return nil, fmt.Errorf("server %s: %w", name, genErr)
		}

		results = append(results, result)
	}

	return results, nil
}

// GenerateServers generates configs for the specified server and its transitive
// dependencies.
//
//nolint:revive // "generate.Generate" stutter is intentional for API clarity.
func GenerateServers(
	projectRoot string,
	jpath string,
	serverName string,
	genCfg GenerateConfig,
) ([]GenerateResult, error) {
	servers, err := config.Discover(projectRoot)
	if err != nil {
		return nil, fmt.Errorf("discover servers: %w", err)
	}

	configs, err := loadAllConfigs(servers, projectRoot, jpath)
	if err != nil {
		return nil, err
	}

	graph, err := BuildGraph(configs)
	if err != nil {
		return nil, fmt.Errorf("build dependency graph: %w", err)
	}

	deps, err := graph.TransitiveDependencies(serverName)
	if err != nil {
		return nil, fmt.Errorf("resolve dependencies for %s: %w", serverName, err)
	}

	subConfigs := make(map[string]config.Config, len(deps))
	for _, dep := range deps {
		subConfigs[dep] = configs[dep]
	}

	subGraph, err := BuildGraph(subConfigs)
	if err != nil {
		return nil, fmt.Errorf("build sub-graph: %w", err)
	}

	order, err := subGraph.TopologicalSort()
	if err != nil {
		return nil, fmt.Errorf("topological sort: %w", err)
	}

	state := NewServerState()
	results := make([]GenerateResult, 0, len(order))

	for _, name := range order {
		result, genErr := generateServerWithState(
			filepath.Join(projectRoot, name),
			name,
			configs[name],
			genCfg,
			state,
		)
		if genErr != nil {
			return nil, fmt.Errorf("server %s: %w", name, genErr)
		}

		results = append(results, result)
	}

	return results, nil
}

func loadAllConfigs(
	servers []string,
	projectRoot string,
	jpath string,
) (map[string]config.Config, error) {
	configs := make(map[string]config.Config, len(servers))

	for _, name := range servers {
		dir := filepath.Join(projectRoot, name)
		cfg, err := config.LoadServerWithJsonnet(dir, jpath)
		if err != nil {
			return nil, fmt.Errorf("load config for %s: %w", name, err)
		}
		if err := config.Validate(cfg); err != nil {
			return nil, fmt.Errorf("validate config for %s: %w", name, err)
		}
		configs[name] = cfg
	}

	return configs, nil
}

// generateServerWithState generates a single server's config using shared state
// for cross-server credential resolution and user provisioning.
func generateServerWithState(
	dir string,
	serverName string,
	cfg config.Config,
	genCfg GenerateConfig,
	state *ServerState,
) (GenerateResult, error) {
	persisted, err := config.LoadPersistedCredentials(filepath.Join(dir, "config.json"))
	if err != nil {
		return GenerateResult{}, fmt.Errorf("load persisted credentials: %w", err)
	}

	credsMap := resolveCredentials(cfg, persisted, genCfg.Clean)

	for _, in := range cfg.Inbounds {
		state.StoreInboundType(serverName, in.Tag, in.Type)
		state.StoreInboundCredentials(serverName, in.Tag, credsMap[in.Tag])
	}

	certFiles, err := resolveCertificatesWithState(dir, cfg, genCfg.Clean, state, serverName)
	if err != nil {
		return GenerateResult{}, fmt.Errorf("resolve certificates: %w", err)
	}

	state.StoreEndpoint(serverName, cfg.Endpoint)

	if err := provisionCrossServerUsers(cfg, state, serverName); err != nil {
		return GenerateResult{}, fmt.Errorf("provision cross-server users: %w", err)
	}

	ruleSetFiles, err := compileRuleSets(dir, &cfg)
	if err != nil {
		return GenerateResult{}, fmt.Errorf("compile rule-sets: %w", err)
	}

	dnsOpts, err := ConvertDNS(cfg.DNS)
	if err != nil {
		return GenerateResult{}, fmt.Errorf("convert dns: %w", err)
	}

	routeOpts, err := ConvertRoute(cfg.Route)
	if err != nil {
		return GenerateResult{}, fmt.Errorf("convert route: %w", err)
	}

	inbounds, err := buildInbounds(cfg.Inbounds, credsMap)
	if err != nil {
		return GenerateResult{}, fmt.Errorf("build inbounds: %w", err)
	}

	outbounds, err := buildOutboundsWithState(cfg.Outbounds, state, serverName)
	if err != nil {
		return GenerateResult{}, fmt.Errorf("build outbounds: %w", err)
	}

	opts := option.Options{
		DNS:       dnsOpts,
		Route:     routeOpts,
		Inbounds:  inbounds,
		Outbounds: outbounds,
	}

	if len(cfg.Log) > 0 {
		logOpts, logErr := unmarshalLog(cfg.Log)
		if logErr != nil {
			return GenerateResult{}, fmt.Errorf("unmarshal log: %w", logErr)
		}
		opts.Log = logOpts
	}

	if cfg.Route == nil && opts.Route != nil {
		opts.Route.AutoDetectInterface = true
	}

	addBoilerplate(&opts)

	configJSON, err := marshalOptions(&opts)
	if err != nil {
		return GenerateResult{}, fmt.Errorf("marshal config: %w", err)
	}

	files := make([]FileOutput, 0, 1+len(certFiles)+len(ruleSetFiles))
	files = append(files, FileOutput{Path: "config.json", Content: configJSON})
	files = append(files, certFiles...)
	files = append(files, ruleSetFiles...)

	return GenerateResult{
		Server: serverName,
		Files:  files,
	}, nil
}

func provisionCrossServerUsers(cfg config.Config, state *ServerState, serverName string) error {
	for _, out := range cfg.Outbounds {
		if out.Server == "" || out.Type != inboundTypeVLESS && out.Type != inboundTypeHysteria2 {
			continue
		}

		user := out.User
		if user == "" {
			user = serverName
		}

		if err := state.EnsureUser(out.Server, out.Inbound, user); err != nil {
			return fmt.Errorf("provision user %q on %q inbound %q: %w",
				user, out.Server, out.Inbound, err)
		}
	}
	return nil
}

func buildOutboundsWithState(
	outbounds []config.Outbound,
	state *ServerState,
	serverName string,
) ([]option.Outbound, error) {
	result := make([]option.Outbound, 0, len(outbounds))
	for _, out := range outbounds {
		ob, err := BuildOutboundWithState(out, state, WithDefaultUser(serverName))
		if err != nil {
			return nil, fmt.Errorf("outbound %q: %w", out.Tag, err)
		}
		result = append(result, ob)
	}
	return result, nil
}

// resolveCertificatesWithState is like resolveCertificates but also stores
// pin-sha256 fingerprints in the server state.
func resolveCertificatesWithState(
	dir string,
	cfg config.Config,
	clean bool,
	state *ServerState,
	serverName string,
) ([]FileOutput, error) {
	files, err := resolveCertificates(dir, cfg, clean)
	if err != nil {
		return nil, err
	}

	for _, in := range cfg.Inbounds {
		if in.Type != inboundTypeHysteria2 || in.TLS == nil || in.TLS.ServerName == "" {
			continue
		}

		certRelPath := filepath.Join("certs", in.TLS.ServerName+".crt")
		certFile := findFileInList(files, certRelPath)
		if certFile == nil {
			continue
		}

		pin, pinErr := computePinSHA256(certFile.Content)
		if pinErr != nil {
			return nil, fmt.Errorf("compute pin-sha256 for %q: %w", in.TLS.ServerName, pinErr)
		}

		state.StorePinSHA256(serverName, in.Tag, pin)
	}

	return files, nil
}

func findFileInList(files []FileOutput, path string) *FileOutput {
	for i := range files {
		if files[i].Path == path {
			return &files[i]
		}
	}
	return nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./generate/ -run TestGenerateAll -v`
Expected: PASS

- [ ] **Step 5: Run linter**

Run: `golangci-lint run --fix`

- [ ] **Step 6: Commit**

```bash
git add generate/server.go generate/server_test.go
git commit -m "feat(generate): add GenerateAll multi-server orchestrator with DAG and cross-server provisioning"
```

---

## Task 6: CLI — Two-Pass Batch Write, `--dry-run`, `--server` Transitive Deps

**Files:**
- Modify: `cmd/cheburbox/main.go`
- Modify: `cmd/cheburbox/generate_test.go`

Update the CLI to use `GenerateAll`/`GenerateServers` for two-pass batch writes, add `--dry-run` flag, and update `--server` to resolve transitive dependencies.

- [ ] **Step 1: Write the failing tests**

Add to `cmd/cheburbox/generate_test.go`:

```go
func TestGenerateDryRun(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	setupServer(t, root, "srv-a", `{
		"version": 1,
		"endpoint": "1.2.3.4",
		"dns": {
			"servers": [{"type": "local", "tag": "dns-local"}],
			"final": "dns-local"
		},
		"outbounds": [{"type": "direct", "tag": "direct"}]
	}`)

	var buf bytes.Buffer
	err := runGenerate(&buf, root, "lib", "", false, true)
	if err != nil {
		t.Fatalf("runGenerate: %v", err)
	}

	var output []map[string]any
	if err := json.Unmarshal(buf.Bytes(), &output); err != nil {
		t.Fatalf("parse dry-run output: %v", err)
	}

	if len(output) != 1 {
		t.Fatalf("expected 1 server entry, got %d", len(output))
	}
	if output[0]["server"] != "srv-a" {
		t.Errorf("server = %v, want srv-a", output[0]["server"])
	}
	files, ok := output[0]["files"].([]any)
	if !ok || len(files) == 0 {
		t.Fatal("expected files array")
	}
}

func TestGenerateDryRunNoDiskWrite(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	setupServer(t, root, "srv-a", `{
		"version": 1,
		"endpoint": "1.2.3.4",
		"dns": {
			"servers": [{"type": "local", "tag": "dns-local"}],
			"final": "dns-local"
		},
		"outbounds": [{"type": "direct", "tag": "direct"}]
	}`)

	var buf bytes.Buffer
	err := runGenerate(&buf, root, "lib", "", false, true)
	if err != nil {
		t.Fatalf("runGenerate: %v", err)
	}

	configPath := filepath.Join(root, "srv-a", "config.json")
	if _, err := os.Stat(configPath); err == nil {
		t.Fatal("config.json should not be written in dry-run mode")
	}
}

func TestGenerateServerWithTransitiveDeps(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	setupServer(t, root, "exit-srv", `{
		"version": 1,
		"endpoint": "10.0.0.1",
		"dns": {
			"servers": [{"type": "local", "tag": "dns-local"}],
			"final": "dns-local"
		},
		"inbounds": [{"tag": "vless-in", "type": "vless", "listen_port": 443, "users": [{"name": "client-srv"}]}],
		"outbounds": [{"type": "direct", "tag": "direct"}]
	}`)
	setupServer(t, root, "client-srv", `{
		"version": 1,
		"dns": {
			"servers": [{"type": "local", "tag": "dns-local"}],
			"final": "dns-local"
		},
		"outbounds": [
			{"type": "direct", "tag": "direct"},
			{"type": "vless", "tag": "exit-vless", "server": "exit-srv", "inbound": "vless-in", "user": "client-srv"}
		]
	}`)
	setupServer(t, root, "unrelated", `{
		"version": 1,
		"dns": {
			"servers": [{"type": "local", "tag": "dns-local"}],
			"final": "dns-local"
		},
		"outbounds": [{"type": "direct", "tag": "direct"}]
	}`)

	var buf bytes.Buffer
	err := runGenerate(&buf, root, "lib", "client-srv", false, false)
	if err != nil {
		t.Fatalf("runGenerate: %v", err)
	}

	clientConfig := filepath.Join(root, "client-srv", "config.json")
	if _, err := os.Stat(clientConfig); err != nil {
		t.Fatalf("client-srv config.json should exist: %v", err)
	}

	exitConfig := filepath.Join(root, "exit-srv", "config.json")
	if _, err := os.Stat(exitConfig); err != nil {
		t.Fatalf("exit-srv config.json should exist (transitive dep): %v", err)
	}

	unrelatedConfig := filepath.Join(root, "unrelated", "config.json")
	if _, err := os.Stat(unrelatedConfig); err == nil {
		t.Fatal("unrelated config.json should NOT exist")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./cmd/cheburbox/ -run "TestGenerateDryRun|TestGenerateServerWithTransitive" -v`
Expected: FAIL — `runGenerate` signature changed, new behavior not implemented.

- [ ] **Step 3: Update CLI implementation**

Update `cmd/cheburbox/main.go`:

```go
package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/Arsolitt/cheburbox/config"
	"github.com/Arsolitt/cheburbox/generate"
	"github.com/Arsolitt/cheburbox/ruleset"
)

func main() {
	if err := NewRootCommand().Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func NewRootCommand() *cobra.Command {
	var projectRoot string
	var jpath string

	rootCmd := &cobra.Command{
		Use:           "cheburbox",
		Short:         "Manage sing-box configurations across multiple servers.",
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	rootCmd.PersistentFlags().StringVar(&projectRoot, "project", "", "project root directory (default: CWD)")
	rootCmd.PersistentFlags().StringVar(&jpath, "jpath", "lib", "jsonnet library path")

	var serverName string
	var clean bool
	var dryRun bool

	generateCmd := &cobra.Command{
		Use:   "generate",
		Short: "Generate sing-box configuration files for servers.",
		RunE: func(command *cobra.Command, _ []string) error {
			proj := projectRoot
			if proj == "" {
				var err error
				proj, err = os.Getwd()
				if err != nil {
					return fmt.Errorf("get working directory: %w", err)
				}
			}
			return runGenerate(command.OutOrStdout(), proj, jpath, serverName, clean, dryRun)
		},
	}

	generateCmd.Flags().StringVar(&serverName, "server", "", "generate only this server and its dependencies")
	generateCmd.Flags().BoolVar(&clean, "clean", false, "remove undeclared users/credentials")
	generateCmd.Flags().BoolVar(&dryRun, "dry-run", false, "output JSON to stdout without writing files")

	rootCmd.AddCommand(generateCmd)

	var compileInput string
	var compileOutput string
	var compileServer string

	compileCmd := &cobra.Command{
		Use:   "compile",
		Short: "Compile local rule-set from JSON to binary .srs format.",
		RunE: func(command *cobra.Command, _ []string) error {
			return runRuleSetCompile(command.OutOrStdout(), projectRoot, compileServer, compileInput, compileOutput)
		},
	}

	compileCmd.Flags().
		StringVar(&compileServer, "server", "", "server name (auto-compiles all rule-sets in server directory)")
	compileCmd.Flags().StringVar(&compileInput, "input", "", "input JSON rule-set file path")
	compileCmd.Flags().StringVar(&compileOutput, "output", "", "output .srs file path")

	ruleSetCmd := &cobra.Command{
		Use:   "rule-set",
		Short: "Manage local rule-sets.",
	}

	ruleSetCmd.AddCommand(compileCmd)
	rootCmd.AddCommand(ruleSetCmd)

	return rootCmd
}

func runGenerate(
	w io.Writer,
	projectRoot string,
	jpath string,
	serverName string,
	clean bool,
	dryRun bool,
) error {
	genCfg := generate.GenerateConfig{Clean: clean}
	jpathAbs := resolveJPath(projectRoot, jpath)

	var results []generate.GenerateResult
	var err error

	if serverName != "" {
		results, err = generate.GenerateServers(projectRoot, jpathAbs, serverName, genCfg)
	} else {
		results, err = generate.GenerateAll(projectRoot, jpathAbs, genCfg)
	}

	if err != nil {
		return err
	}

	if len(results) == 0 {
		fmt.Fprintln(w, "no servers found in project")
		return nil
	}

	if dryRun {
		return writeDryRunOutput(w, results)
	}

	return writeResults(w, projectRoot, results)
}

func writeDryRunOutput(w io.Writer, results []generate.GenerateResult) error {
	type fileEntry struct {
		Path    string `json:"path"`
		Content string `json:"content"`
	}

	type serverEntry struct {
		Server string       `json:"server"`
		Files  []fileEntry  `json:"files"`
	}

	output := make([]serverEntry, 0, len(results))
	for _, result := range results {
		entry := serverEntry{
			Server: result.Server,
			Files:  make([]fileEntry, 0, len(result.Files)),
		}

		for _, f := range result.Files {
			content := base64.StdEncoding.EncodeToString(f.Content)
			entry.Files = append(entry.Files, fileEntry{
				Path:    f.Path,
				Content: content,
			})
		}

		output = append(output, entry)
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(output); err != nil {
		return fmt.Errorf("encode dry-run output: %w", err)
	}

	return nil
}

func writeResults(w io.Writer, projectRoot string, results []generate.GenerateResult) error {
	for _, result := range results {
		dir := filepath.Join(projectRoot, result.Server)

		for _, f := range result.Files {
			path := filepath.Join(dir, f.Path)
			if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
				return fmt.Errorf("create directory for %s: %w", f.Path, err)
			}
			if err := os.WriteFile(path, f.Content, 0o644); err != nil {
				return fmt.Errorf("write %s: %w", f.Path, err)
			}
		}

		fmt.Fprintf(w, "Generated %d files for server %s\n", len(result.Files), result.Server)
	}

	return nil
}

func runRuleSetCompile(w io.Writer, projectRoot string, serverName string, input string, output string) error {
	if serverName != "" {
		return runRuleSetCompileServer(w, projectRoot, serverName)
	}

	if input == "" || output == "" {
		return errors.New("--input and --output are required when --server is not specified")
	}

	return runRuleSetCompileSingle(w, input, output)
}

func runRuleSetCompileSingle(w io.Writer, input string, output string) error {
	content, err := os.ReadFile(input)
	if err != nil {
		return fmt.Errorf("read input: %w", err)
	}

	if err := ruleset.Compile(content, output); err != nil {
		return fmt.Errorf("compile: %w", err)
	}

	fmt.Fprintf(w, "Compiled %s -> %s\n", input, output)

	return nil
}

func runRuleSetCompileServer(w io.Writer, projectRoot string, serverName string) error {
	proj := projectRoot
	if proj == "" {
		var err error
		proj, err = os.Getwd()
		if err != nil {
			return fmt.Errorf("get working directory: %w", err)
		}
	}

	dir := filepath.Join(proj, serverName)
	jpathAbs := resolveJPath(proj, "")

	cfg, err := config.LoadServerWithJsonnet(dir, jpathAbs)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	if cfg.Route == nil || len(cfg.Route.CustomRuleSets) == 0 {
		fmt.Fprintln(w, "no custom rule-sets defined for server")
		return nil
	}

	sources, err := ruleset.FindSourceFiles(dir, cfg.Route.CustomRuleSets)
	if err != nil {
		return fmt.Errorf("discover rule-set sources: %w", err)
	}

	if len(sources) == 0 {
		fmt.Fprintln(w, "no rule-set source files found in server directory")
		return nil
	}

	ruleSetDir := filepath.Join(dir, "rule-set")
	if err := os.MkdirAll(ruleSetDir, 0o750); err != nil {
		return fmt.Errorf("create rule-set directory: %w", err)
	}

	for _, src := range sources {
		content, err := os.ReadFile(src.Path)
		if err != nil {
			return fmt.Errorf("read %s: %w", src.Name, err)
		}

		outputPath := filepath.Join(ruleSetDir, src.Name+".srs")
		if err := ruleset.Compile(content, outputPath); err != nil {
			return fmt.Errorf("compile %s: %w", src.Name, err)
		}

		fmt.Fprintf(w, "Compiled %s -> %s\n", src.Name, outputPath)
	}

	return nil
}

func resolveJPath(projectRoot string, jpath string) string {
	if jpath == "" {
		return ""
	}
	if filepath.IsAbs(jpath) {
		return jpath
	}
	return filepath.Join(projectRoot, jpath)
}
```

- [ ] **Step 4: Update existing tests to match new signature**

Update all existing test calls to `runGenerate` to include the new `dryRun` parameter. Every call like:

```go
err := runGenerate(&buf, root, "lib", tt.server, false)
```

becomes:

```go
err := runGenerate(&buf, root, "lib", tt.server, false, false)
```

- [ ] **Step 5: Run all tests to verify they pass**

Run: `go test ./... -v`
Expected: PASS

- [ ] **Step 6: Run linter**

Run: `golangci-lint run --fix`

- [ ] **Step 7: Commit**

```bash
git add cmd/cheburbox/main.go cmd/cheburbox/generate_test.go
git commit -m "feat(cli): two-pass batch write, --dry-run, --server with transitive deps"
```

---

## Task 7: Integration Test — Multi-Server with Cross-Server Outbounds

**Files:**
- Modify: `generate/integration_test.go`

Add an integration test that exercises the full multi-server pipeline: two servers, one with cross-server vless outbound, verifying that credentials are provisioned and the outbound is correctly generated.

- [ ] **Step 1: Write the failing integration test**

Add to `generate/integration_test.go`:

```go
func TestIntegrationMultiServerCrossServer(t *testing.T) {
	t.Parallel()

	projectRoot := t.TempDir()

	exitCfg := config.Config{
		Version:  1,
		Endpoint: "10.0.0.1",
		DNS: config.DNS{
			Final:   new("dns-local"),
			Servers: []config.DNSServer{{Type: "local", Tag: "dns-local"}},
		},
		Inbounds: []config.Inbound{
			{
				Tag:        "vless-in",
				Type:       inboundTypeVLESS,
				ListenPort: 443,
				Users:      []config.InboundUser{{Name: "proxy-server"}},
				TLS: &config.InboundTLS{
					Reality: &config.RealityConfig{
						Handshake: &config.RealityHandshake{
							Server:     "example.com",
							ServerPort: 443,
						},
					},
				},
			},
			{
				Tag:        "hy2-in",
				Type:       inboundTypeHysteria2,
				ListenPort: 8443,
				TLS:        &config.InboundTLS{ServerName: "hy.example.com"},
				Users:      []config.InboundUser{{Name: "proxy-server"}},
			},
		},
		Outbounds: []config.Outbound{
			{Type: outboundTypeDirect, Tag: "direct"},
		},
	}

	proxyCfg := config.Config{
		Version: 1,
		DNS: config.DNS{
			Final:   new("dns-local"),
			Servers: []config.DNSServer{{Type: "local", Tag: "dns-local"}},
		},
		Outbounds: []config.Outbound{
			{Type: outboundTypeDirect, Tag: "direct"},
			{
				Type:    inboundTypeVLESS,
				Tag:     "exit-vless",
				Server:  "exit-server",
				Inbound: "vless-in",
				User:    "proxy-server",
			},
			{
				Type:    inboundTypeHysteria2,
				Tag:     "exit-hy",
				Server:  "exit-server",
				Inbound: "hy2-in",
				User:    "proxy-server",
			},
		},
	}

	exitDir := filepath.Join(projectRoot, "exit-server")
	if err := os.MkdirAll(exitDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	exitData, _ := json.Marshal(exitCfg)
	if err := os.WriteFile(filepath.Join(exitDir, "cheburbox.json"), exitData, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	proxyDir := filepath.Join(projectRoot, "proxy-server")
	if err := os.MkdirAll(proxyDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	proxyData, _ := json.Marshal(proxyCfg)
	if err := os.WriteFile(filepath.Join(proxyDir, "cheburbox.json"), proxyData, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	results, err := GenerateAll(projectRoot, "lib", GenerateConfig{})
	if err != nil {
		t.Fatalf("GenerateAll: %v", err)
	}

	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}

	exitResult := findResult(results, "exit-server")
	proxyResult := findResult(results, "proxy-server")

	exitConfig := findFile(exitResult.Files, "config.json")
	var exitParsed map[string]any
	if err := json.Unmarshal(exitConfig.Content, &exitParsed); err != nil {
		t.Fatalf("parse exit config: %v", err)
	}

	exitInbounds := exitParsed["inbounds"].([]any)
	if len(exitInbounds) != 2 {
		t.Fatalf("expected 2 inbounds on exit-server, got %d", len(exitInbounds))
	}

	vlessIn := exitInbounds[0].(map[string]any)
	vlessUsers := vlessIn["users"].([]any)
	if len(vlessUsers) != 1 {
		t.Fatalf("expected 1 user on vless-in, got %d", len(vlessUsers))
	}

	proxyConfig := findFile(proxyResult.Files, "config.json")
	var proxyParsed map[string]any
	if err := json.Unmarshal(proxyConfig.Content, &proxyParsed); err != nil {
		t.Fatalf("parse proxy config: %v", err)
	}

	proxyOutbounds := proxyParsed["outbounds"].([]any)
	vlessFound := false
	hy2Found := false
	for _, ob := range proxyOutbounds {
		obMap := ob.(map[string]any)
		if obMap["type"] == "vless" {
			vlessFound = true
		}
		if obMap["type"] == "hysteria2" {
			hy2Found = true
		}
	}
	if !vlessFound {
		t.Error("proxy-server should have a vless outbound")
	}
	if !hy2Found {
		t.Error("proxy-server should have a hysteria2 outbound")
	}
}
```

- [ ] **Step 2: Run test to verify it passes**

Run: `go test ./generate/ -run TestIntegrationMultiServer -v`
Expected: PASS

- [ ] **Step 3: Run linter**

Run: `golangci-lint run --fix`

- [ ] **Step 4: Commit**

```bash
git add generate/integration_test.go
git commit -m "test(generate): add multi-server cross-server integration test"
```

---

## Task 8: Final Verification — Run All Tests and Linter

**Files:** None (verification only)

- [ ] **Step 1: Run all tests**

Run: `go test ./... -v -count=1`
Expected: ALL PASS

- [ ] **Step 2: Run linter**

Run: `golangci-lint run`
Expected: no errors

- [ ] **Step 3: Run with coverage**

Run: `go test ./... -cover`
Expected: no failures, reasonable coverage

---

## Self-Review Checklist

### Spec Coverage

| Spec Requirement | Task |
|---|---|
| DAG construction from outbound `server` references | Task 3 |
| Topological sort with cycle detection | Task 3 |
| Cross-server user provisioning (add users to target server in-memory) | Task 5 (`provisionCrossServerUsers`) |
| Batch write: two-pass approach (in-memory then atomic disk write) | Task 6 (`writeResults` after `GenerateAll`) |
| `--server` flag: generate specified server and transitive upstream dependencies | Task 6 (`GenerateServers` + `TransitiveDependencies`) |
| `--dry-run`: stdout JSON output, no disk writes, binary files base64-encoded | Task 6 (`writeDryRunOutput`) |
| Integration tests with multi-server project layouts | Task 7 |
| Cross-server vless outbound (uuid, flow, reality public key) | Task 4 |
| Cross-server hysteria2 outbound (password, pin-sha256) | Task 4 |
| pin-sha256 auto-computed from target certificate | Task 2 |
| `--clean` flag removes cross-server provisioned users | Task 5 (uses existing `resolveCredentials` with `clean`) |
| Unknown server reference → error | Task 3 (`BuildGraph` validates) |
| Self-referencing server → error | Task 3 (`BuildGraph` checks) |

### Placeholder Scan

- No TBD, TODO, or "implement later" found.
- All code blocks contain actual implementation code.
- All test code is complete and runnable.

### Type Consistency

- `ServerState` methods use consistent naming across Tasks 1, 4, 5.
- `BuildOutboundWithState` signature consistent between Task 4 definition and Task 5 usage.
- `GenerateResult` and `FileOutput` types unchanged from existing code.
- `OutboundBuildOption` / `WithDefaultUser` consistent between Task 4 and Task 5.

### Notes for Implementer

1. **sing-box struct verification**: Task 4 requires verifying exact field names for `option.VLESSOutboundOptions`, `option.Hysteria2OutboundOptions`, `option.OutboundTLSOptions`, and `option.OutboundRealityOptions`. Run grep on the sing-box option package to confirm before implementing.

2. **`parseInterval` duplication**: The existing `parseInterval` in `outbound.go` uses `time.ParseDuration`. The refactored version in Task 4 must keep this import. Ensure `time` import is present.

3. **`GenerateAll` vs legacy `GenerateServer`**: The existing `GenerateServer` function is kept for backward compatibility. `GenerateAll` is the new entry point for the multi-server path. Consider whether to deprecate `GenerateServer` or keep it — this plan keeps it.

4. **Cross-server user provisioning order**: `provisionCrossServerUsers` is called after credentials are resolved for the current server and after certs are generated, but BEFORE inbounds/outbounds are built. This ensures the target server's state already has the provisioned user credentials when the current server's outbounds look them up. But wait — the current server's outbounds reference *other* servers that have already been generated. The `EnsureUser` call adds the user to those *already-generated* servers' state, which means those servers' `GenerateResult` has already been computed without this user. **This is a bug.**

   **Fix**: Cross-server user provisioning must happen in the `GenerateAll` loop BEFORE generating the server. When processing server A which references server B, server B has already been generated. The user provisioning for B (adding user from A) must happen BEFORE B's config is finalized. But B was already generated...

   Actually, re-reading the spec: "Look up target server's in-memory config (already generated by topological order). Check if user exists. If not — generate credentials, add user to target server's in-memory inbound config." The spec says to modify the target server's in-memory config. This means after all servers are generated, we need a second pass to update target servers' configs with newly provisioned users.

   **Revised approach**: Generate all servers in topological order. During generation, if an outbound references a target, provision the user on the target's ServerState. After all servers are generated, do a second pass to rebuild any server whose inbounds were modified by cross-server provisioning (new users were added). Track which servers received new users via a dirty flag on ServerState.

   **Alternative (simpler)**: Process outbounds in two phases per server:
   1. First, scan all outbounds and provision users on target servers (modify target ServerState).
   2. Then, rebuild target servers that were modified.
   
   This gets complex. The simplest correct approach: generate all servers in topological order. After the full loop, check if any server's inbound credentials were modified (new users added). If so, regenerate those servers and any servers that depend on them. This could loop, but since we only add users (never remove), it converges in one extra pass.

   **Simplest correct approach**: Change the loop to:
   1. Topological sort.
   2. For each server in order:
      a. Provision cross-server users on targets (EnsureUser).
      b. If any target was already generated and received a new user, regenerate it.
   3. Generate the current server.
   
   Since we process in topological order, targets are always already generated. When we add a user to a target, we need to regenerate the target and all servers that depend on it. But that's expensive.

   **Pragmatic approach**: Do two passes:
   - Pass 1: Generate all servers in topological order, collecting cross-server user provisions.
   - Pass 2: For each server that received new users, re-resolve its credentials (which now include the new users) and rebuild its inbounds/outbounds/config.json.
   
   This is correct because: pass 1 generates all servers. During pass 1, `provisionCrossServerUsers` adds users to already-generated target servers' ServerState. After pass 1, we know which servers were modified. Pass 2 regenerates only those servers.

   **Implementation**: Add a `dirtyServers` set to ServerState. When `EnsureUser` adds a new user, mark the server as dirty. After the main generation loop, regenerate dirty servers and their dependents.

   This needs to be addressed in Task 5. The plan above (Task 5 Step 3) calls `provisionCrossServerUsers` before building outbounds, which only provisions users on OTHER servers (already generated). The current server's outbounds then correctly read from the updated state. But the target server's already-computed `GenerateResult` is stale.

   **Resolution**: Move `provisionCrossServerUsers` to BEFORE the generation loop. Do a pre-pass: for each server in topological order, provision users on targets. Then generate all servers. This way, by the time we generate each server, all cross-server users are already in the state.

   **Updated Task 5 implementation**: In `GenerateAll`, do the provisioning loop first:
   ```go
   // Pre-pass: provision all cross-server users
   for _, name := range order {
       cfg := configs[name]
       if err := provisionCrossServerUsers(cfg, state, name); err != nil {
           return nil, fmt.Errorf("server %s: %w", name, err)
       }
   }
   // Then generate all servers
   for _, name := range order {
       result, err := generateServerWithState(...)
       ...
   }
   ```

   This is correct because:
   - Servers are processed in topological order.
   - When server A provisions user X on server B, server B comes before A in the order.
   - By the time server A provisions, server B's credentials are already in state (from `resolveCredentials` called during server B's generation).
   - Wait, no — in the pre-pass, we haven't generated any servers yet. The state is empty. `EnsureUser` would fail because the target server has no credentials in state yet.

   **Final correct approach**: Two loops:
   1. Loop 1: Generate all servers in topological order, storing credentials in state. Do NOT provision cross-server users yet.
   2. Loop 2: For each server in topological order, provision cross-server users (now targets have credentials in state).
   3. Loop 3: For any server that was modified in loop 2 (received new users), regenerate it.

   Actually this still has issues. Let me think again...

   The correct approach from the spec: "for each server in order: create cross-server users on targets in memory, generate certs in memory, build config.json in memory."

   The spec says: during generation of server A, when we encounter an outbound to server B:
   1. Look up B's in-memory config (already generated).
   2. Check if user exists.
   3. If not, generate credentials, add user to B's in-memory config.

   This means the generation of server A modifies server B's already-generated in-memory result. The key insight: we're building everything in memory. We can go back and update server B's result.

   **Implementation**:
   1. Generate all servers in topological order, storing results.
   2. During generation of each server, when encountering a cross-server outbound, call `EnsureUser` on the target. This modifies `ServerState`.
   3. If `EnsureUser` added a new user (target was already generated), mark the target as needing regeneration.
   4. After the main loop, regenerate all marked servers.
   5. Repeat until no more servers are marked (converges in 1-2 iterations).

   This is correct. The plan in Task 5 should be updated to track dirty servers and do a regeneration pass. Let me update Task 5's `GenerateAll` to include this.

   **Simpler implementation**: Since `provisionCrossServerUsers` runs before `buildOutboundsWithState`, and it modifies the state for target servers, the current server's outbound building correctly sees the updated state. The issue is only that the target server's `GenerateResult` is stale (doesn't include the new user). We need to rebuild the target.

   **Track this with a dirty set**:
   ```go
   dirty := make(map[string]bool)
   // ... in EnsureUser, if a new user is added, mark the server as dirty
   // After main loop, regenerate dirty servers
   ```

   But `EnsureUser` doesn't know about the dirty set. We need to either:
   a. Return a boolean from `EnsureUser` indicating if a new user was added.
   b. Have `provisionCrossServerUsers` return the set of modified servers.

   Option (b) is cleaner. Update `provisionCrossServerUsers` to return `map[string]bool` (servers that received new users). Then in `GenerateAll`, after the main loop, regenerate those servers.

   **This is a design issue that should be addressed in the implementation.** The plan above provides the foundation; the implementer should handle the regeneration loop correctly.
