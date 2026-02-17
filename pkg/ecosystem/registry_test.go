package ecosystem

import (
	"context"
	"fmt"
	"testing"
)

// mockPlugin implements Plugin for testing.
type mockPlugin struct {
	name        string
	displayName string
	priority    int
	detectFunc  func(path string) bool
	scanFunc    func(path string) (*ScanResult, error)
}

func (m *mockPlugin) Info() PluginInfo {
	return PluginInfo{
		Name:        m.name,
		DisplayName: m.displayName,
		Priority:    m.priority,
	}
}

func (m *mockPlugin) Detect(ctx context.Context, path string) bool {
	if m.detectFunc != nil {
		return m.detectFunc(path)
	}
	return false
}

func (m *mockPlugin) Scan(ctx context.Context, path string) (*ScanResult, error) {
	if m.scanFunc != nil {
		return m.scanFunc(path)
	}
	return &ScanResult{Ecosystem: m.name}, nil
}

func (m *mockPlugin) GetFix(ctx context.Context, pkg Package, vuln Vulnerability) (*FixAction, error) {
	return &FixAction{Type: "upgrade"}, nil
}

func TestNewRegistry(t *testing.T) {
	r := NewRegistry()
	if r == nil {
		t.Fatal("NewRegistry returned nil")
	}
	if r.plugins == nil {
		t.Error("plugins map is nil")
	}
}

func TestRegister(t *testing.T) {
	r := NewRegistry()

	t.Run("successful registration", func(t *testing.T) {
		p := &mockPlugin{name: "test1"}
		err := r.Register(p)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}

		got, ok := r.Get("test1")
		if !ok {
			t.Error("plugin not found after registration")
		}
		if got != p {
			t.Error("retrieved plugin doesn't match registered plugin")
		}
	})

	t.Run("duplicate registration", func(t *testing.T) {
		p1 := &mockPlugin{name: "dup"}
		p2 := &mockPlugin{name: "dup"}

		if err := r.Register(p1); err != nil {
			t.Fatalf("first registration failed: %v", err)
		}

		err := r.Register(p2)
		if err == nil {
			t.Error("expected error for duplicate registration")
		}
	})

	t.Run("empty name", func(t *testing.T) {
		p := &mockPlugin{name: ""}
		err := r.Register(p)
		if err == nil {
			t.Error("expected error for empty name")
		}
	})
}

func TestGet(t *testing.T) {
	r := NewRegistry()
	p := &mockPlugin{name: "myplug"}
	r.Register(p)

	t.Run("existing plugin", func(t *testing.T) {
		got, ok := r.Get("myplug")
		if !ok {
			t.Error("expected to find plugin")
		}
		if got.Info().Name != "myplug" {
			t.Errorf("unexpected plugin name: %s", got.Info().Name)
		}
	})

	t.Run("nonexistent plugin", func(t *testing.T) {
		_, ok := r.Get("nonexistent")
		if ok {
			t.Error("expected not to find plugin")
		}
	})
}

func TestList(t *testing.T) {
	r := NewRegistry()

	// Register plugins with different priorities
	plugins := []*mockPlugin{
		{name: "low", priority: 10},
		{name: "high", priority: 100},
		{name: "medium", priority: 50},
	}

	for _, p := range plugins {
		if err := r.Register(p); err != nil {
			t.Fatalf("registration failed: %v", err)
		}
	}

	list := r.List()
	if len(list) != 3 {
		t.Errorf("expected 3 plugins, got %d", len(list))
	}

	// Should be sorted by priority (highest first)
	if list[0].Info().Name != "high" {
		t.Errorf("expected 'high' first, got %q", list[0].Info().Name)
	}
	if list[1].Info().Name != "medium" {
		t.Errorf("expected 'medium' second, got %q", list[1].Info().Name)
	}
	if list[2].Info().Name != "low" {
		t.Errorf("expected 'low' third, got %q", list[2].Info().Name)
	}
}

func TestDetect(t *testing.T) {
	r := NewRegistry()
	ctx := context.Background()

	// Register plugins that detect specific paths
	r.Register(&mockPlugin{
		name:     "npm",
		priority: 100,
		detectFunc: func(path string) bool {
			return path == "/project/npm" || path == "/project/both"
		},
	})
	r.Register(&mockPlugin{
		name:     "go",
		priority: 90,
		detectFunc: func(path string) bool {
			return path == "/project/go" || path == "/project/both"
		},
	})

	t.Run("single match", func(t *testing.T) {
		matches := r.Detect(ctx, "/project/npm")
		if len(matches) != 1 {
			t.Errorf("expected 1 match, got %d", len(matches))
		}
		if len(matches) > 0 && matches[0].Info().Name != "npm" {
			t.Errorf("expected npm, got %s", matches[0].Info().Name)
		}
	})

	t.Run("multiple matches", func(t *testing.T) {
		matches := r.Detect(ctx, "/project/both")
		if len(matches) != 2 {
			t.Errorf("expected 2 matches, got %d", len(matches))
		}
		// Should be sorted by priority
		if len(matches) >= 2 {
			if matches[0].Info().Name != "npm" {
				t.Errorf("expected npm first, got %s", matches[0].Info().Name)
			}
			if matches[1].Info().Name != "go" {
				t.Errorf("expected go second, got %s", matches[1].Info().Name)
			}
		}
	})

	t.Run("no matches", func(t *testing.T) {
		matches := r.Detect(ctx, "/project/unknown")
		if len(matches) != 0 {
			t.Errorf("expected 0 matches, got %d", len(matches))
		}
	})
}

func TestScanAll(t *testing.T) {
	ctx := context.Background()

	t.Run("successful scan", func(t *testing.T) {
		r := NewRegistry()
		r.Register(&mockPlugin{
			name:       "npm",
			detectFunc: func(path string) bool { return true },
			scanFunc: func(path string) (*ScanResult, error) {
				return &ScanResult{
					Ecosystem:       "npm",
					PackagesScanned: 10,
				}, nil
			},
		})

		results, err := r.ScanAll(ctx, "/project")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(results) != 1 {
			t.Errorf("expected 1 result, got %d", len(results))
		}
		if results[0].PackagesScanned != 10 {
			t.Errorf("expected 10 packages, got %d", results[0].PackagesScanned)
		}
	})

	t.Run("no matching plugins", func(t *testing.T) {
		r := NewRegistry()
		r.Register(&mockPlugin{
			name:       "npm",
			detectFunc: func(path string) bool { return false },
		})

		_, err := r.ScanAll(ctx, "/project")
		if err == nil {
			t.Error("expected error for no matching plugins")
		}
	})

	t.Run("all scans fail returns error", func(t *testing.T) {
		r := NewRegistry()
		r.Register(&mockPlugin{
			name:       "failing",
			detectFunc: func(path string) bool { return true },
			scanFunc: func(path string) (*ScanResult, error) {
				return nil, context.Canceled
			},
		})

		results, err := r.ScanAll(ctx, "/project")
		// When ALL scans fail, ScanAll should return an error
		if err == nil {
			t.Fatal("ScanAll should return error when all scans fail")
		}
		// Results should still be populated with error details
		if len(results) != 1 {
			t.Fatalf("expected 1 result, got %d", len(results))
		}
		if len(results[0].Errors) == 0 {
			t.Error("expected errors to be captured in result")
		}
		if results[0].Status != ScanStatusFailed {
			t.Errorf("expected status Failed, got %s", results[0].Status)
		}
	})

	t.Run("partial failure succeeds with warning", func(t *testing.T) {
		r := NewRegistry()
		r.Register(&mockPlugin{
			name:       "failing",
			priority:   100,
			detectFunc: func(path string) bool { return true },
			scanFunc: func(path string) (*ScanResult, error) {
				return nil, context.Canceled
			},
		})
		r.Register(&mockPlugin{
			name:       "succeeding",
			priority:   90,
			detectFunc: func(path string) bool { return true },
			scanFunc: func(path string) (*ScanResult, error) {
				return &ScanResult{Ecosystem: "succeeding", PackagesScanned: 5, Status: ScanStatusSuccess}, nil
			},
		})

		results, err := r.ScanAll(ctx, "/project")
		// When at least one scan succeeds, no error should be returned
		if err != nil {
			t.Fatalf("ScanAll should not return error for partial failure: %v", err)
		}
		if len(results) != 2 {
			t.Fatalf("expected 2 results, got %d", len(results))
		}

		// Check that we have one failed and one successful
		var failedCount, successCount int
		for _, r := range results {
			if r.Failed() {
				failedCount++
			}
			if r.Success() {
				successCount++
			}
		}
		if failedCount != 1 {
			t.Errorf("expected 1 failed result, got %d", failedCount)
		}
		if successCount != 1 {
			t.Errorf("expected 1 successful result, got %d", successCount)
		}
	})
}

func TestPackageStruct(t *testing.T) {
	pkg := Package{
		Name:      "lodash",
		Version:   "4.17.21",
		Ecosystem: "npm",
		Source:    "/project/package-lock.json",
		Direct:    true,
	}

	if pkg.Name != "lodash" {
		t.Errorf("unexpected name: %s", pkg.Name)
	}
	if pkg.Version != "4.17.21" {
		t.Errorf("unexpected version: %s", pkg.Version)
	}
}

func TestVulnerabilityStruct(t *testing.T) {
	score := 7.5
	vuln := Vulnerability{
		ID:         "CVE-2021-23337",
		Aliases:    []string{"GHSA-xxxx"},
		Severity:   "HIGH",
		CVSSScore:  &score,
		Summary:    "Prototype pollution",
		FixVersion: "4.17.21",
	}

	if vuln.ID != "CVE-2021-23337" {
		t.Errorf("unexpected ID: %s", vuln.ID)
	}
	if vuln.CVSSScore == nil || *vuln.CVSSScore != 7.5 {
		t.Errorf("unexpected CVSS score")
	}
}

func TestScanResultStruct(t *testing.T) {
	result := ScanResult{
		Ecosystem:       "npm",
		PackagesScanned: 100,
		Findings: []Finding{
			{
				Package: Package{Name: "lodash", Version: "4.17.15"},
				Vulnerabilities: []Vulnerability{
					{ID: "CVE-2021-23337"},
				},
			},
		},
	}

	if result.Ecosystem != "npm" {
		t.Errorf("unexpected ecosystem: %s", result.Ecosystem)
	}
	if len(result.Findings) != 1 {
		t.Errorf("expected 1 finding, got %d", len(result.Findings))
	}
}

func TestFixActionStruct(t *testing.T) {
	fix := FixAction{
		Type:          "upgrade",
		Command:       "npm install lodash@4.17.21",
		Description:   "Upgrade lodash",
		TargetVersion: "4.17.21",
		Breaking:      false,
	}

	if fix.Type != "upgrade" {
		t.Errorf("unexpected type: %s", fix.Type)
	}
	if fix.Command == "" {
		t.Error("expected command")
	}
}

// TestConcurrentRegistryAccess tests registry for race conditions.
// Run with: go test -race ./pkg/ecosystem/...
func TestConcurrentRegistryAccess(t *testing.T) {
	r := NewRegistry()

	// Register initial plugins
	for i := 0; i < 5; i++ {
		p := &mockPlugin{name: fmt.Sprintf("init-%d", i), priority: i * 10}
		r.Register(p)
	}

	done := make(chan bool)
	ctx := context.Background()

	// Concurrent reads
	for i := 0; i < 10; i++ {
		go func() {
			for j := 0; j < 100; j++ {
				r.List()
				r.Get("init-0")
				r.Detect(ctx, "/project")
			}
			done <- true
		}()
	}

	// Concurrent registrations (will fail after first one for duplicates)
	for i := 0; i < 10; i++ {
		go func(n int) {
			for j := 0; j < 10; j++ {
				p := &mockPlugin{name: fmt.Sprintf("concurrent-%d-%d", n, j)}
				r.Register(p) // May fail, that's ok
			}
			done <- true
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < 20; i++ {
		<-done
	}
}

// TestConcurrentPluginOperations tests plugin operations under concurrent load.
func TestConcurrentPluginOperations(t *testing.T) {
	r := NewRegistry()
	ctx := context.Background()

	// Register a plugin with scan function
	r.Register(&mockPlugin{
		name:       "concurrent-scan",
		detectFunc: func(path string) bool { return true },
		scanFunc: func(path string) (*ScanResult, error) {
			return &ScanResult{Ecosystem: "test", PackagesScanned: 1}, nil
		},
	})

	done := make(chan bool)

	// Concurrent scans
	for i := 0; i < 10; i++ {
		go func() {
			for j := 0; j < 50; j++ {
				r.ScanAll(ctx, "/project")
			}
			done <- true
		}()
	}

	// Concurrent detects
	for i := 0; i < 10; i++ {
		go func() {
			for j := 0; j < 50; j++ {
				r.Detect(ctx, "/project")
			}
			done <- true
		}()
	}

	// Wait for all goroutines
	for i := 0; i < 20; i++ {
		<-done
	}
}

func TestNormalizeEcosystem(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		// Direct plugin names (lowercase)
		{"npm lowercase", "npm", "npm"},
		{"pip lowercase", "pip", "pip"},
		{"go lowercase", "go", "go"},

		// Case normalization
		{"NPM uppercase", "NPM", "npm"},
		{"Go mixed case", "Go", "go"},
		{"PIP uppercase", "PIP", "pip"},

		// OSV ecosystem names → plugin names
		{"PyPI uppercase", "PyPI", "pip"},
		{"pypi lowercase", "pypi", "pip"},
		{"PYPI all caps", "PYPI", "pip"},

		// Whitespace handling
		{"with leading space", " npm", "npm"},
		{"with trailing space", "npm ", "npm"},
		{"with both spaces", " pip ", "pip"},
		{"PyPI with spaces", " PyPI ", "pip"},

		// Edge cases
		{"empty string", "", ""},
		{"unknown ecosystem", "maven", "maven"},
		{"unknown mixed case", "Maven", "maven"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := NormalizeEcosystem(tt.input)
			if result != tt.expected {
				t.Errorf("NormalizeEcosystem(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}
