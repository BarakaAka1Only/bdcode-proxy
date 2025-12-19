package memory

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/hasirciogluhq/xdatabase-proxy/cmd/proxy/internal/core"
)

type Resolver struct {
	backends map[string]string
	mu       sync.RWMutex
}

// NewResolver creates a new memory resolver from a comma-separated string
// Format: "db1=host1:port,db2=host2:port"
func NewResolver(mappingStr string) (*Resolver, error) {
	backends := make(map[string]string)
	if mappingStr == "" {
		return &Resolver{backends: backends}, nil
	}

	pairs := strings.Split(mappingStr, ",")
	for _, pair := range pairs {
		parts := strings.Split(strings.TrimSpace(pair), "=")
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid mapping format: %s", pair)
		}
		name := strings.TrimSpace(parts[0])
		addr := strings.TrimSpace(parts[1])
		backends[name] = addr
	}

	return &Resolver{backends: backends}, nil
}

func (r *Resolver) Resolve(ctx context.Context, metadata core.RoutingMetadata) (string, error) {
	r.mu.RLock()
	addr, ok := r.backends[metadata["database"]]
	r.mu.RUnlock()

	if !ok {
		return "", fmt.Errorf("backend not found for database: %s", metadata["database"])
	}

	fmt.Printf("MemoryResolver: Routing %s to %s\n", metadata["database"], addr)
	return addr, nil
}
