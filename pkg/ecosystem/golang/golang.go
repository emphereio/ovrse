// Package golang provides the Go ecosystem plugin.
package golang

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/emphereio/ovrse/pkg/ecosystem"
)

func init() {
	_ = ecosystem.Register(&Plugin{})
}

// Plugin implements the Go ecosystem.
type Plugin struct{}

// Info returns plugin metadata.
func (p *Plugin) Info() ecosystem.PluginInfo {
	return ecosystem.PluginInfo{
		Name:        "go",
		DisplayName: "Go Modules",
		Description: "Scans go.sum for Go module vulnerabilities",
		FilePatterns: []string{
			"go.sum",
			"go.mod",
		},
		Priority: 100,
	}
}

// Detect checks if this is a Go project.
func (p *Plugin) Detect(ctx context.Context, path string) bool {
	goSum := filepath.Join(path, "go.sum")
	if _, err := os.Stat(goSum); err == nil {
		return true
	}
	goMod := filepath.Join(path, "go.mod")
	if _, err := os.Stat(goMod); err == nil {
		return true
	}
	return false
}

// Scan parses go.sum and checks for vulnerabilities.
func (p *Plugin) Scan(ctx context.Context, path string) (*ecosystem.ScanResult, error) {
	goSum := filepath.Join(path, "go.sum")
	packages, err := parseGoSum(goSum)
	if err != nil {
		// Try go.mod if go.sum doesn't exist
		goMod := filepath.Join(path, "go.mod")
		packages, err = parseGoMod(goMod)
		if err != nil {
			return nil, fmt.Errorf("failed to parse go.sum or go.mod: %w", err)
		}
	}

	// Query OSV for vulnerabilities
	findings, err := ecosystem.DefaultOSVClient.CheckPackages(ctx, packages)
	if err != nil {
		// Vulnerability check failure is a critical error - cannot guarantee safety
		return nil, fmt.Errorf("vulnerability check failed: %w", err)
	}

	return &ecosystem.ScanResult{
		Ecosystem:       "go", // Must match plugin Name for registry lookups
		PackagesScanned: len(packages),
		Findings:        findings,
		Status:          ecosystem.ScanStatusSuccess,
	}, nil
}

// GetFix returns the go command to fix a vulnerability.
func (p *Plugin) GetFix(ctx context.Context, pkg ecosystem.Package, vuln ecosystem.Vulnerability) (*ecosystem.FixAction, error) {
	if vuln.FixVersion == "" {
		return &ecosystem.FixAction{
			Type:        "workaround",
			Description: fmt.Sprintf("No fix available for %s. Consider removing or replacing the module.", vuln.ID),
		}, nil
	}

	return &ecosystem.FixAction{
		Type:          "upgrade",
		Command:       fmt.Sprintf("go get %s@%s", pkg.Name, vuln.FixVersion),
		Description:   fmt.Sprintf("Upgrade %s from %s to %s", pkg.Name, pkg.Version, vuln.FixVersion),
		TargetVersion: vuln.FixVersion,
	}, nil
}

// NativeAudit runs govulncheck if available.
func (p *Plugin) NativeAudit(ctx context.Context, path string) (*ecosystem.ScanResult, error) {
	// Check if govulncheck is available
	if _, err := exec.LookPath("govulncheck"); err != nil {
		return nil, fmt.Errorf("govulncheck not installed (go install golang.org/x/vuln/cmd/govulncheck@latest)")
	}

	cmd := exec.CommandContext(ctx, "govulncheck", "-json", "./...")
	cmd.Dir = path

	output, err := cmd.Output()
	if err != nil {
		// govulncheck returns non-zero when vulnerabilities found
		if len(output) == 0 {
			return nil, fmt.Errorf("govulncheck failed: %w", err)
		}
	}

	// TODO: Parse govulncheck JSON output
	// For now, fall back to OSV scan
	return p.Scan(ctx, path)
}

// go.sum line format: module version hash
// Example: github.com/pkg/errors v0.9.1 h1:xxx
// Note: OSV Go ecosystem expects versions WITH the v prefix
var goSumLineRegex = regexp.MustCompile(`^([^\s]+)\s+(v[^\s/]+)(?:/go\.mod)?\s+`)

// parseGoSum parses go.sum and returns packages.
func parseGoSum(path string) ([]ecosystem.Package, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer func() { _ = file.Close() }()

	var packages []ecosystem.Package
	seen := make(map[string]bool)

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		matches := goSumLineRegex.FindStringSubmatch(line)
		if matches == nil {
			continue
		}

		name := matches[1]
		version := matches[2]

		// Clean up version
		version = strings.TrimSuffix(version, "+incompatible")

		pkgKey := name + "@" + version
		if seen[pkgKey] {
			continue
		}
		seen[pkgKey] = true

		packages = append(packages, ecosystem.Package{
			Name:      name,
			Version:   version,
			Ecosystem: "Go",
			Source:    path,
		})
	}

	return packages, scanner.Err()
}

// parseGoMod parses go.mod require statements.
func parseGoMod(path string) ([]ecosystem.Package, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()

	var packages []ecosystem.Package
	inRequire := false

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if strings.HasPrefix(line, "require (") {
			inRequire = true
			continue
		}
		if inRequire && line == ")" {
			inRequire = false
			continue
		}

		// Handle single-line require
		if strings.HasPrefix(line, "require ") {
			line = strings.TrimPrefix(line, "require ")
		} else if !inRequire {
			continue
		}

		// Parse "module version" or "module version // indirect"
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}

		name := parts[0]
		version := parts[1]

		packages = append(packages, ecosystem.Package{
			Name:      name,
			Version:   version,
			Ecosystem: "Go",
			Source:    path,
		})
	}

	return packages, scanner.Err()
}
