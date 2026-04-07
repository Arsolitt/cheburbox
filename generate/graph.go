package generate

import (
	"errors"
	"fmt"

	"github.com/Arsolitt/cheburbox/config"
)

// Edge represents a directed dependency from one server to another.
type Edge struct {
	From string
	To   string
}

// Graph represents a directed graph of server dependencies.
type Graph struct {
	Nodes map[string]bool
	Edges []Edge
}

// BuildGraph constructs a dependency graph from a set of server configurations.
// Each outbound with a non-empty Server field creates an edge from the owning server to the target.
// Returns an error for self-references, unknown server references, or dependency cycles.
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

	if err := g.detectCycle(); err != nil {
		return nil, err
	}

	return g, nil
}

func (g *Graph) detectCycle() error {
	const (
		stateUnvisited  = 0
		stateInProgress = 1
		stateDone       = 2
	)

	visited := make(map[string]int, len(g.Nodes))

	var dfs func(name string) error
	dfs = func(name string) error {
		if visited[name] == stateDone {
			return nil
		}
		if visited[name] == stateInProgress {
			return errors.New("cycle detected in server dependencies")
		}
		visited[name] = stateInProgress
		for _, edge := range g.Edges {
			if edge.From == name {
				if err := dfs(edge.To); err != nil {
					return err
				}
			}
		}
		visited[name] = stateDone
		return nil
	}

	for name := range g.Nodes {
		if visited[name] == stateUnvisited {
			if err := dfs(name); err != nil {
				return err
			}
		}
	}

	return nil
}

// TopologicalSort returns servers in dependency order: servers with no dependencies come first.
// Returns an error if a cycle is detected.
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
		return nil, errors.New("cycle detected in server dependencies")
	}

	return result, nil
}

// TransitiveDependencies returns all servers transitively depended on by the given server,
// including the server itself.
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
