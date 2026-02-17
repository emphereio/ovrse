package golang

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

	if info.Name != "go" {
		t.Errorf("expected name 'go', got %q", info.Name)
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

	t.Run("with go.sum", func(t *testing.T) {
		tmpDir := t.TempDir()

		// Should not detect empty directory
		if p.Detect(ctx, tmpDir) {
			t.Error("should not detect empty directory")
		}

		// Should detect with go.sum
		goSum := filepath.Join(tmpDir, "go.sum")
		if err := os.WriteFile(goSum, []byte("module v1.0.0 h1:xxx\n"), 0644); err != nil {
			t.Fatal(err)
		}
		if !p.Detect(ctx, tmpDir) {
			t.Error("should detect with go.sum")
		}
	})

	t.Run("with go.mod only", func(t *testing.T) {
		tmpDir := t.TempDir()
		goMod := filepath.Join(tmpDir, "go.mod")
		content := `module example.com/test

go 1.21

require github.com/pkg/errors v0.9.1
`
		if err := os.WriteFile(goMod, []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
		if !p.Detect(ctx, tmpDir) {
			t.Error("should detect with go.mod")
		}
	})
}

func TestParseGoSum(t *testing.T) {
	content := `github.com/pkg/errors v0.9.1 h1:FEBLx1zS214owpjy7qsBeixbURkuhQAwrK5UwLGTwt4=
github.com/pkg/errors v0.9.1/go.mod h1:bwawxfHBFNV+L2hUp1rHADufV3IMtnDRdf1r5NINEl0=
github.com/stretchr/testify v1.8.0 h1:pSgiaMZlXftHpm5L7V1+rVB+AZJydKsMxsQBIJw4PKk=
github.com/stretchr/testify v1.8.0/go.mod h1:yNjHg4UonilssWZ8iaSj1OCr/vHnekPRkoO+kdMU+MU=
golang.org/x/sys v0.5.0 h1:MUK/U/4lj1t1oPg0HfuXDN/Z1wv31ZJ/YcPiGccS4DU=
golang.org/x/sys v0.5.0/go.mod h1:oPkhp1MJrh7nUepCBck5+mAzfO9JrbApNNgaTdGDITg=
`
	tmpDir := t.TempDir()
	goSum := filepath.Join(tmpDir, "go.sum")
	if err := os.WriteFile(goSum, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	packages, err := parseGoSum(goSum)
	if err != nil {
		t.Fatalf("parseGoSum failed: %v", err)
	}

	// Should have 3 unique packages (deduplicated from 6 lines)
	if len(packages) != 3 {
		t.Errorf("expected 3 packages, got %d", len(packages))
		for _, pkg := range packages {
			t.Logf("  %s@%s", pkg.Name, pkg.Version)
		}
	}

	// Verify packages
	expected := map[string]string{
		"github.com/pkg/errors":    "v0.9.1",
		"github.com/stretchr/testify": "v1.8.0",
		"golang.org/x/sys":         "v0.5.0",
	}

	for _, pkg := range packages {
		if expected[pkg.Name] != pkg.Version {
			t.Errorf("package %s: expected version %s, got %s", pkg.Name, expected[pkg.Name], pkg.Version)
		}
		if pkg.Ecosystem != "Go" {
			t.Errorf("expected ecosystem 'Go', got %q", pkg.Ecosystem)
		}
	}
}

func TestParseGoSumWithIncompatible(t *testing.T) {
	content := `github.com/some/module v2.0.0+incompatible h1:xxx=
github.com/some/module v2.0.0+incompatible/go.mod h1:xxx=
`
	tmpDir := t.TempDir()
	goSum := filepath.Join(tmpDir, "go.sum")
	if err := os.WriteFile(goSum, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	packages, err := parseGoSum(goSum)
	if err != nil {
		t.Fatalf("parseGoSum failed: %v", err)
	}

	if len(packages) != 1 {
		t.Errorf("expected 1 package, got %d", len(packages))
		return
	}

	// +incompatible should be stripped
	if packages[0].Version != "v2.0.0" {
		t.Errorf("expected version 'v2.0.0', got %q", packages[0].Version)
	}
}

func TestParseGoMod(t *testing.T) {
	content := `module example.com/myproject

go 1.21

require (
	github.com/pkg/errors v0.9.1
	github.com/stretchr/testify v1.8.0
	golang.org/x/sys v0.5.0 // indirect
)

require github.com/single/require v1.0.0
`
	tmpDir := t.TempDir()
	goMod := filepath.Join(tmpDir, "go.mod")
	if err := os.WriteFile(goMod, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	packages, err := parseGoMod(goMod)
	if err != nil {
		t.Fatalf("parseGoMod failed: %v", err)
	}

	if len(packages) != 4 {
		t.Errorf("expected 4 packages, got %d", len(packages))
		for _, pkg := range packages {
			t.Logf("  %s@%s", pkg.Name, pkg.Version)
		}
	}
}

func TestParseGoModSingleRequire(t *testing.T) {
	content := `module example.com/simple

go 1.21

require github.com/pkg/errors v0.9.1
`
	tmpDir := t.TempDir()
	goMod := filepath.Join(tmpDir, "go.mod")
	if err := os.WriteFile(goMod, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	packages, err := parseGoMod(goMod)
	if err != nil {
		t.Fatalf("parseGoMod failed: %v", err)
	}

	if len(packages) != 1 {
		t.Errorf("expected 1 package, got %d", len(packages))
		return
	}

	if packages[0].Name != "github.com/pkg/errors" {
		t.Errorf("unexpected package name: %s", packages[0].Name)
	}
	if packages[0].Version != "v0.9.1" {
		t.Errorf("unexpected version: %s", packages[0].Version)
	}
}

func TestGetFix(t *testing.T) {
	p := &Plugin{}
	ctx := context.Background()

	t.Run("with fix version", func(t *testing.T) {
		pkg := ecosystem.Package{
			Name:      "github.com/pkg/errors",
			Version:   "v0.9.0",
			Ecosystem: "Go",
		}
		vuln := ecosystem.Vulnerability{
			ID:         "GO-2023-1234",
			FixVersion: "v0.9.1",
		}

		fix, err := p.GetFix(ctx, pkg, vuln)
		if err != nil {
			t.Fatalf("GetFix failed: %v", err)
		}

		if fix.Type != "upgrade" {
			t.Errorf("expected type 'upgrade', got %q", fix.Type)
		}
		if fix.Command != "go get github.com/pkg/errors@v0.9.1" {
			t.Errorf("unexpected command: %s", fix.Command)
		}
		if fix.TargetVersion != "v0.9.1" {
			t.Errorf("expected target version 'v0.9.1', got %q", fix.TargetVersion)
		}
	})

	t.Run("without fix version", func(t *testing.T) {
		pkg := ecosystem.Package{
			Name:      "github.com/vulnerable/module",
			Version:   "v1.0.0",
			Ecosystem: "Go",
		}
		vuln := ecosystem.Vulnerability{
			ID: "GO-2024-9999",
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

func TestParseGoSumEmpty(t *testing.T) {
	tmpDir := t.TempDir()
	goSum := filepath.Join(tmpDir, "go.sum")
	if err := os.WriteFile(goSum, []byte(""), 0644); err != nil {
		t.Fatal(err)
	}

	packages, err := parseGoSum(goSum)
	if err != nil {
		t.Fatalf("parseGoSum failed: %v", err)
	}

	if len(packages) != 0 {
		t.Errorf("expected 0 packages, got %d", len(packages))
	}
}

func TestParseGoSumInvalid(t *testing.T) {
	// Test non-existent file
	_, err := parseGoSum("/nonexistent/go.sum")
	if err == nil {
		t.Error("expected error for non-existent file")
	}
}

func TestVersionWithVPrefix(t *testing.T) {
	// OSV Go ecosystem expects versions WITH the v prefix
	content := `github.com/test/module v1.2.3 h1:xxx=
`
	tmpDir := t.TempDir()
	goSum := filepath.Join(tmpDir, "go.sum")
	if err := os.WriteFile(goSum, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	packages, err := parseGoSum(goSum)
	if err != nil {
		t.Fatalf("parseGoSum failed: %v", err)
	}

	if len(packages) != 1 {
		t.Fatalf("expected 1 package, got %d", len(packages))
	}

	// Version should retain v prefix
	if packages[0].Version != "v1.2.3" {
		t.Errorf("expected version 'v1.2.3', got %q", packages[0].Version)
	}
}
