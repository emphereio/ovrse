package npm

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/emphereio/ovrse/pkg/ecosystem"
)

func TestPluginInfo(t *testing.T) {
	p := &Plugin{}
	info := p.Info()

	if info.Name != "npm" {
		t.Errorf("expected name 'npm', got %q", info.Name)
	}
	if info.DisplayName == "" {
		t.Error("expected non-empty display name")
	}
	if len(info.FilePatterns) == 0 {
		t.Error("expected file patterns")
	}
}

func TestDetect(t *testing.T) {
	p := &Plugin{}
	ctx := context.Background()

	t.Run("with package-lock.json", func(t *testing.T) {
		tmpDir := t.TempDir()

		// Should not detect with only package.json (can't scan it)
		pkgJSON := filepath.Join(tmpDir, "package.json")
		if err := os.WriteFile(pkgJSON, []byte(`{"name":"test"}`), 0644); err != nil {
			t.Fatal(err)
		}
		if p.Detect(ctx, tmpDir) {
			t.Error("should not detect with only package.json")
		}

		// Should detect with package-lock.json
		lockFile := filepath.Join(tmpDir, "package-lock.json")
		if err := os.WriteFile(lockFile, []byte(`{"lockfileVersion":2}`), 0644); err != nil {
			t.Fatal(err)
		}
		if !p.Detect(ctx, tmpDir) {
			t.Error("should detect with package-lock.json")
		}
	})

	t.Run("empty directory", func(t *testing.T) {
		tmpDir := t.TempDir()
		if p.Detect(ctx, tmpDir) {
			t.Error("should not detect empty directory")
		}
	})
}

func TestParseLockFileV2(t *testing.T) {
	lockContent := `{
		"name": "test-project",
		"lockfileVersion": 2,
		"packages": {
			"": {
				"name": "test-project"
			},
			"node_modules/lodash": {
				"version": "4.17.21"
			},
			"node_modules/express": {
				"version": "4.18.2"
			},
			"node_modules/@types/node": {
				"version": "18.0.0"
			}
		}
	}`

	tmpDir := t.TempDir()
	lockFile := filepath.Join(tmpDir, "package-lock.json")
	if err := os.WriteFile(lockFile, []byte(lockContent), 0644); err != nil {
		t.Fatal(err)
	}

	packages, err := parseLockFile(lockFile)
	if err != nil {
		t.Fatalf("parseLockFile failed: %v", err)
	}

	if len(packages) != 3 {
		t.Errorf("expected 3 packages, got %d", len(packages))
	}

	// Verify package names are extracted correctly
	names := make(map[string]string)
	for _, pkg := range packages {
		names[pkg.Name] = pkg.Version
	}

	expected := map[string]string{
		"lodash":       "4.17.21",
		"express":      "4.18.2",
		"@types/node":  "18.0.0",
	}

	for name, version := range expected {
		if names[name] != version {
			t.Errorf("package %s: expected version %s, got %s", name, version, names[name])
		}
	}
}

func TestParseLockFileV1(t *testing.T) {
	lockContent := `{
		"name": "test-project",
		"lockfileVersion": 1,
		"dependencies": {
			"axios": {
				"version": "1.4.0"
			},
			"debug": {
				"version": "4.3.4"
			}
		}
	}`

	tmpDir := t.TempDir()
	lockFile := filepath.Join(tmpDir, "package-lock.json")
	if err := os.WriteFile(lockFile, []byte(lockContent), 0644); err != nil {
		t.Fatal(err)
	}

	packages, err := parseLockFile(lockFile)
	if err != nil {
		t.Fatalf("parseLockFile failed: %v", err)
	}

	if len(packages) != 2 {
		t.Errorf("expected 2 packages, got %d", len(packages))
	}

	// Verify packages
	names := make(map[string]bool)
	for _, pkg := range packages {
		names[pkg.Name] = true
		if pkg.Ecosystem != "npm" {
			t.Errorf("expected ecosystem 'npm', got %q", pkg.Ecosystem)
		}
	}

	if !names["axios"] || !names["debug"] {
		t.Error("missing expected packages")
	}
}

func TestParseLockFileEmpty(t *testing.T) {
	lockContent := `{
		"name": "empty-project",
		"lockfileVersion": 2,
		"packages": {
			"": {}
		}
	}`

	tmpDir := t.TempDir()
	lockFile := filepath.Join(tmpDir, "package-lock.json")
	if err := os.WriteFile(lockFile, []byte(lockContent), 0644); err != nil {
		t.Fatal(err)
	}

	packages, err := parseLockFile(lockFile)
	if err != nil {
		t.Fatalf("parseLockFile failed: %v", err)
	}

	if len(packages) != 0 {
		t.Errorf("expected 0 packages, got %d", len(packages))
	}
}

func TestParseLockFileNestedDependencies(t *testing.T) {
	// Test scoped packages and nested node_modules
	lockContent := `{
		"lockfileVersion": 3,
		"packages": {
			"node_modules/@scope/package": {
				"version": "1.0.0"
			},
			"node_modules/parent/node_modules/nested": {
				"version": "2.0.0"
			}
		}
	}`

	tmpDir := t.TempDir()
	lockFile := filepath.Join(tmpDir, "package-lock.json")
	if err := os.WriteFile(lockFile, []byte(lockContent), 0644); err != nil {
		t.Fatal(err)
	}

	packages, err := parseLockFile(lockFile)
	if err != nil {
		t.Fatalf("parseLockFile failed: %v", err)
	}

	if len(packages) != 2 {
		t.Errorf("expected 2 packages, got %d", len(packages))
	}

	// Check that names are extracted correctly
	names := make(map[string]bool)
	for _, pkg := range packages {
		names[pkg.Name] = true
	}

	if !names["@scope/package"] {
		t.Error("missing @scope/package")
	}
	if !names["nested"] {
		t.Error("missing nested package")
	}
}

func TestGetFix(t *testing.T) {
	p := &Plugin{}
	ctx := context.Background()

	t.Run("with fix version", func(t *testing.T) {
		pkg := ecosystem.Package{
			Name:      "lodash",
			Version:   "4.17.15",
			Ecosystem: "npm",
		}
		vuln := ecosystem.Vulnerability{
			ID:         "CVE-2021-23337",
			FixVersion: "4.17.21",
		}

		fix, err := p.GetFix(ctx, pkg, vuln)
		if err != nil {
			t.Fatalf("GetFix failed: %v", err)
		}

		if fix.Type != "upgrade" {
			t.Errorf("expected type 'upgrade', got %q", fix.Type)
		}
		if fix.Command != "npm install lodash@4.17.21" {
			t.Errorf("unexpected command: %s", fix.Command)
		}
		if fix.TargetVersion != "4.17.21" {
			t.Errorf("expected target version '4.17.21', got %q", fix.TargetVersion)
		}
	})

	t.Run("without fix version", func(t *testing.T) {
		pkg := ecosystem.Package{
			Name:      "vulnerable-pkg",
			Version:   "1.0.0",
			Ecosystem: "npm",
		}
		vuln := ecosystem.Vulnerability{
			ID: "CVE-2024-9999",
		}

		fix, err := p.GetFix(ctx, pkg, vuln)
		if err != nil {
			t.Fatalf("GetFix failed: %v", err)
		}

		if fix.Type != "workaround" {
			t.Errorf("expected type 'workaround', got %q", fix.Type)
		}
	})
}

func TestParseLockFileInvalid(t *testing.T) {
	tmpDir := t.TempDir()
	lockFile := filepath.Join(tmpDir, "package-lock.json")

	// Test invalid JSON
	if err := os.WriteFile(lockFile, []byte("not json"), 0644); err != nil {
		t.Fatal(err)
	}

	_, err := parseLockFile(lockFile)
	if err == nil {
		t.Error("expected error for invalid JSON")
	}

	// Test non-existent file
	_, err = parseLockFile(filepath.Join(tmpDir, "nonexistent.json"))
	if err == nil {
		t.Error("expected error for non-existent file")
	}
}

func TestDeduplication(t *testing.T) {
	// Packages should be deduplicated by name@version
	lockContent := `{
		"lockfileVersion": 2,
		"packages": {
			"node_modules/lodash": {
				"version": "4.17.21"
			},
			"node_modules/other/node_modules/lodash": {
				"version": "4.17.21"
			}
		}
	}`

	tmpDir := t.TempDir()
	lockFile := filepath.Join(tmpDir, "package-lock.json")
	if err := os.WriteFile(lockFile, []byte(lockContent), 0644); err != nil {
		t.Fatal(err)
	}

	packages, err := parseLockFile(lockFile)
	if err != nil {
		t.Fatalf("parseLockFile failed: %v", err)
	}

	if len(packages) != 1 {
		t.Errorf("expected 1 package (deduplicated), got %d", len(packages))
	}
}
