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

		if p.Detect(ctx, tmpDir) {
			t.Error("should not detect empty directory")
		}

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

	if len(packages) != 3 {
		t.Errorf("expected 3 packages, got %d", len(packages))
		for _, pkg := range packages {
			t.Logf("  %s@%s", pkg.Name, pkg.Version)
		}
	}

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
	_, err := parseGoSum("/nonexistent/go.sum")
	if err == nil {
		t.Error("expected error for non-existent file")
	}
}

func TestVersionWithVPrefix(t *testing.T) {
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

	if packages[0].Version != "v1.2.3" {
		t.Errorf("expected version 'v1.2.3', got %q", packages[0].Version)
	}
}

func TestParseGoModWithReplace(t *testing.T) {
	content := `module example.com/myproject

go 1.21

require (
	github.com/old/module v1.0.0
	github.com/local/module v1.0.0
	github.com/kept/module v1.5.0
)

replace github.com/old/module => github.com/new/module v1.2.0

replace github.com/local/module => ../local
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

	if len(packages) != 3 {
		t.Fatalf("expected 3 packages, got %d", len(packages))
	}

	pkgMap := make(map[string]ecosystem.Package)
	for _, pkg := range packages {
		pkgMap[pkg.Name] = pkg
	}

	if pkg, ok := pkgMap["github.com/new/module"]; !ok {
		t.Error("expected replaced module github.com/new/module")
	} else if pkg.Version != "v1.2.0" {
		t.Errorf("expected version v1.2.0, got %s", pkg.Version)
	}

	if pkg, ok := pkgMap["github.com/local/module"]; !ok {
		t.Error("expected original module github.com/local/module (local replace ignored)")
	} else if pkg.Version != "v1.0.0" {
		t.Errorf("expected version v1.0.0, got %s", pkg.Version)
	}

	if pkg, ok := pkgMap["github.com/kept/module"]; !ok {
		t.Error("expected module github.com/kept/module")
	} else if pkg.Version != "v1.5.0" {
		t.Errorf("expected version v1.5.0, got %s", pkg.Version)
	}
}

func TestParseGoModDirectIndirect(t *testing.T) {
	content := `module example.com/myproject

go 1.21

require (
	github.com/direct/dep v1.0.0
	github.com/indirect/dep v1.3.0 // indirect
)
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

	if len(packages) != 2 {
		t.Fatalf("expected 2 packages, got %d", len(packages))
	}

	for _, pkg := range packages {
		switch pkg.Name {
		case "github.com/direct/dep":
			if !pkg.Direct {
				t.Error("expected github.com/direct/dep to be Direct=true")
			}
		case "github.com/indirect/dep":
			if pkg.Direct {
				t.Error("expected github.com/indirect/dep to be Direct=false")
			}
		default:
			t.Errorf("unexpected package: %s", pkg.Name)
		}
	}
}

func TestScanPrefersGoMod(t *testing.T) {
	tmpDir := t.TempDir()

	goModContent := `module example.com/test

go 1.21

require (
	github.com/pkg/errors v0.9.1
	github.com/stretchr/testify v1.8.0
)
`
	if err := os.WriteFile(filepath.Join(tmpDir, "go.mod"), []byte(goModContent), 0644); err != nil {
		t.Fatal(err)
	}

	goSumContent := `github.com/pkg/errors v0.9.1 h1:FEBLx1zS214owpjy7qsBeixbURkuhQAwrK5UwLGTwt4=
github.com/pkg/errors v0.9.1/go.mod h1:bwawxfHBFNV+L2hUp1rHADufV3IMtnDRdf1r5NINEl0=
github.com/stretchr/testify v1.8.0 h1:pSgiaMZlXftHpm5L7V1+rVB+AZJydKsMxsQBIJw4PKk=
github.com/stretchr/testify v1.8.0/go.mod h1:yNjHg4UonilssWZ8iaSj1OCr/vHnekPRkoO+kdMU+MU=
github.com/davecgh/go-spew v1.1.1 h1:vj9j/u1bqnvCEfJOwUhtlOARqs3+rkHYY13jYWTU97c=
github.com/davecgh/go-spew v1.1.1/go.mod h1:J7Y8YcW2NihsgmVo/mv3lAwl/skON4iLHjSsI+c5H38=
github.com/pmezard/go-difflib v1.0.0 h1:4DBwDE0NGyQoBHbLQYPwSUPoCMWR5BEzIk/f1lZbAQM=
github.com/pmezard/go-difflib v1.0.0/go.mod h1:iKH77E/DIRtfOGp7rxMxcFuKD9Tt6pToFo5MfzbppSQ=
`
	if err := os.WriteFile(filepath.Join(tmpDir, "go.sum"), []byte(goSumContent), 0644); err != nil {
		t.Fatal(err)
	}

	goModPackages, err := parseGoMod(filepath.Join(tmpDir, "go.mod"))
	if err != nil {
		t.Fatalf("parseGoMod failed: %v", err)
	}

	goSumPackages, err := parseGoSum(filepath.Join(tmpDir, "go.sum"))
	if err != nil {
		t.Fatalf("parseGoSum failed: %v", err)
	}

	if len(goModPackages) >= len(goSumPackages) {
		t.Errorf("go.mod should have fewer packages than go.sum: go.mod=%d, go.sum=%d",
			len(goModPackages), len(goSumPackages))
	}

	if len(goModPackages) != 2 {
		t.Errorf("expected 2 packages from go.mod, got %d", len(goModPackages))
	}
	if len(goSumPackages) != 4 {
		t.Errorf("expected 4 packages from go.sum, got %d", len(goSumPackages))
	}
}

func TestParseGoModVersionSpecificReplace(t *testing.T) {
	content := `module example.com/myproject

go 1.21

require (
	github.com/foo/bar v1.0.0
	github.com/foo/bar/v2 v2.0.0
)

replace github.com/foo/bar v1.0.0 => github.com/foo/bar v1.0.1
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

	if len(packages) != 2 {
		t.Fatalf("expected 2 packages, got %d", len(packages))
	}

	pkgMap := make(map[string]ecosystem.Package)
	for _, pkg := range packages {
		pkgMap[pkg.Name] = pkg
	}

	if pkg := pkgMap["github.com/foo/bar"]; pkg.Version != "v1.0.1" {
		t.Errorf("expected v1.0.0 to be replaced with v1.0.1, got %s", pkg.Version)
	}

	if pkg := pkgMap["github.com/foo/bar/v2"]; pkg.Version != "v2.0.0" {
		t.Errorf("expected v2.0.0 to be unchanged, got %s", pkg.Version)
	}
}

func TestParseGoModMalformed(t *testing.T) {
	content := `this is not a valid go.mod file
{{{garbage
`
	tmpDir := t.TempDir()
	goMod := filepath.Join(tmpDir, "go.mod")
	if err := os.WriteFile(goMod, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	_, err := parseGoMod(goMod)
	if err == nil {
		t.Fatal("expected error for malformed go.mod")
	}
}

func TestScanFailsFastOnMalformedGoMod(t *testing.T) {
	tmpDir := t.TempDir()

	if err := os.WriteFile(filepath.Join(tmpDir, "go.mod"), []byte("{{{garbage"), 0644); err != nil {
		t.Fatal(err)
	}

	goSumContent := `github.com/pkg/errors v0.9.1 h1:FEBLx1zS214owpjy7qsBeixbURkuhQAwrK5UwLGTwt4=
`
	if err := os.WriteFile(filepath.Join(tmpDir, "go.sum"), []byte(goSumContent), 0644); err != nil {
		t.Fatal(err)
	}

	p := &Plugin{}
	_, err := p.Scan(context.Background(), tmpDir)
	if err == nil {
		t.Fatal("expected error for malformed go.mod, should not fall back to go.sum")
	}
}
