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
