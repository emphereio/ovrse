package ecosystem

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
)

// Registry manages ecosystem plugins.
type Registry struct {
	mu      sync.RWMutex
	plugins map[string]Plugin
}

// DefaultRegistry is the global plugin registry.
var DefaultRegistry = NewRegistry()

// NewRegistry creates a new plugin registry.
func NewRegistry() *Registry {
	return &Registry{
		plugins: make(map[string]Plugin),
	}
}

// Register adds a plugin to the registry.
func (r *Registry) Register(plugin Plugin) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	info := plugin.Info()
	if info.Name == "" {
		return fmt.Errorf("plugin name cannot be empty")
	}

	if _, exists := r.plugins[info.Name]; exists {
		return fmt.Errorf("plugin %q already registered", info.Name)
	}

	r.plugins[info.Name] = plugin
	return nil
}

// Get returns a plugin by name.
func (r *Registry) Get(name string) (Plugin, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	plugin, ok := r.plugins[name]
	return plugin, ok
}

// List returns all registered plugins, sorted by priority (highest first).
func (r *Registry) List() []Plugin {
	r.mu.RLock()
	defer r.mu.RUnlock()

	plugins := make([]Plugin, 0, len(r.plugins))
	for _, p := range r.plugins {
		plugins = append(plugins, p)
	}

	sort.Slice(plugins, func(i, j int) bool {
		return plugins[i].Info().Priority > plugins[j].Info().Priority
	})

	return plugins
}

// Detect finds all plugins that can handle the given path.
func (r *Registry) Detect(ctx context.Context, path string) []Plugin {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var matches []Plugin
	for _, p := range r.plugins {
		if p.Detect(ctx, path) {
			matches = append(matches, p)
		}
	}

	// Sort by priority
	sort.Slice(matches, func(i, j int) bool {
		return matches[i].Info().Priority > matches[j].Info().Priority
	})

	return matches
}

// ScanAll scans a path with all matching plugins.
// Returns an error only if ALL plugins fail. Partial failures are recorded in results.
func (r *Registry) ScanAll(ctx context.Context, path string) ([]*ScanResult, error) {
	plugins := r.Detect(ctx, path)
	if len(plugins) == 0 {
		return nil, fmt.Errorf("no plugins found for path: %s", path)
	}

	var results []*ScanResult
	var failedCount int

	for _, p := range plugins {
		result, err := p.Scan(ctx, path)
		if err != nil {
			// Plugin scan failed completely
			result = &ScanResult{
				Ecosystem: p.Info().Name,
				Errors:    []string{err.Error()},
				Status:    ScanStatusFailed,
			}
			failedCount++
		} else if result == nil {
			// Plugin returned nil result without error - treat as failure
			result = &ScanResult{
				Ecosystem: p.Info().Name,
				Errors:    []string{"plugin returned nil result"},
				Status:    ScanStatusFailed,
			}
			failedCount++
		} else if result.Status == "" {
			// Plugin didn't set status, infer from errors
			if len(result.Errors) > 0 {
				result.Status = ScanStatusPartial
			} else {
				result.Status = ScanStatusSuccess
			}
		}
		results = append(results, result)
	}

	// If ALL plugins failed, return an error
	if failedCount == len(plugins) {
		var errMsgs []string
		for _, r := range results {
			for _, e := range r.Errors {
				errMsgs = append(errMsgs, fmt.Sprintf("[%s] %s", r.Ecosystem, e))
			}
		}
		return results, fmt.Errorf("all scans failed: %s", strings.Join(errMsgs, "; "))
	}

	return results, nil
}

// NativeAuditAll runs native audit on all matching plugins that support it.
func (r *Registry) NativeAuditAll(ctx context.Context, path string) ([]*ScanResult, error) {
	plugins := r.Detect(ctx, path)
	if len(plugins) == 0 {
		return nil, fmt.Errorf("no plugins found for path: %s", path)
	}

	var results []*ScanResult
	var failedCount int
	var auditableCount int

	for _, p := range plugins {
		na, ok := p.(PluginWithNativeAudit)
		if !ok {
			continue
		}
		auditableCount++

		result, err := na.NativeAudit(ctx, path)
		if err != nil {
			result = &ScanResult{
				Ecosystem: p.Info().Name,
				Errors:    []string{err.Error()},
				Status:    ScanStatusFailed,
			}
			failedCount++
		} else if result == nil {
			result = &ScanResult{
				Ecosystem: p.Info().Name,
				Errors:    []string{"native audit returned nil result"},
				Status:    ScanStatusFailed,
			}
			failedCount++
		} else if result.Status == "" {
			if len(result.Errors) > 0 {
				result.Status = ScanStatusPartial
			} else {
				result.Status = ScanStatusSuccess
			}
		}
		results = append(results, result)
	}

	if auditableCount == 0 {
		return nil, fmt.Errorf("no plugins with native audit support found for path: %s", path)
	}

	if failedCount == auditableCount {
		var errMsgs []string
		for _, r := range results {
			for _, e := range r.Errors {
				errMsgs = append(errMsgs, fmt.Sprintf("[%s] %s", r.Ecosystem, e))
			}
		}
		return results, fmt.Errorf("all native audits failed: %s", strings.Join(errMsgs, "; "))
	}

	return results, nil
}

// NativeAuditAll runs native audit with all matching plugins from the default registry.
func NativeAuditAll(ctx context.Context, path string) ([]*ScanResult, error) {
	return DefaultRegistry.NativeAuditAll(ctx, path)
}

// Register adds a plugin to the default registry.
func Register(plugin Plugin) error {
	return DefaultRegistry.Register(plugin)
}

// Get returns a plugin from the default registry.
func Get(name string) (Plugin, bool) {
	return DefaultRegistry.Get(name)
}

// List returns all plugins from the default registry.
func List() []Plugin {
	return DefaultRegistry.List()
}

// Detect finds matching plugins from the default registry.
func Detect(ctx context.Context, path string) []Plugin {
	return DefaultRegistry.Detect(ctx, path)
}

// ScanAll scans with all matching plugins from the default registry.
func ScanAll(ctx context.Context, path string) ([]*ScanResult, error) {
	return DefaultRegistry.ScanAll(ctx, path)
}

// ecosystemAliases maps OSV ecosystem names to plugin names.
// OSV uses "PyPI" but our plugin registers as "pip".
var ecosystemAliases = map[string]string{
	"pypi": "pip",
}

// NormalizeEcosystem converts ecosystem identifiers to plugin names.
// Handles case normalization and OSV→plugin name mapping (e.g., "PyPI" → "pip").
func NormalizeEcosystem(eco string) string {
	normalized := strings.ToLower(strings.TrimSpace(eco))
	if alias, ok := ecosystemAliases[normalized]; ok {
		return alias
	}
	return normalized
}
