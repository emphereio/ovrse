// Package pip provides the Python/pip ecosystem plugin.
package pip

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
	"github.com/emphereio/ovrse/pkg/logging"
)

func init() {
	_ = ecosystem.Register(&Plugin{})
}

// Plugin implements the pip ecosystem.
type Plugin struct{}

// Info returns plugin metadata.
func (p *Plugin) Info() ecosystem.PluginInfo {
	return ecosystem.PluginInfo{
		Name:        "pip",
		DisplayName: "Python (pip)",
		Description: "Scans requirements.txt for Python package vulnerabilities",
		FilePatterns: []string{
			"requirements.txt",
			"requirements-*.txt",
			"requirements/*.txt",
		},
		Priority: 100,
	}
}

// Detect checks if this is a Python project with scannable requirements files.
func (p *Plugin) Detect(ctx context.Context, path string) bool {
	// Only detect if we have files we can actually scan
	reqFiles := findRequirementsFiles(path)
	return len(reqFiles) > 0
}

// Scan parses requirements.txt and checks for vulnerabilities.
func (p *Plugin) Scan(ctx context.Context, path string) (*ecosystem.ScanResult, error) {
	logger := logging.WithComponent("ecosystem.pip")
	logger.Debug().Str("path", path).Msg("scanning pip project")

	// Find all requirements files
	reqFiles := findRequirementsFiles(path)
	if len(reqFiles) == 0 {
		return nil, fmt.Errorf("no requirements.txt files found")
	}
	logger.Debug().Int("files", len(reqFiles)).Msg("found requirements files")

	var allPackages []ecosystem.Package
	var parseErrors []string
	seen := make(map[string]bool)

	for _, reqFile := range reqFiles {
		packages, err := parseRequirements(reqFile)
		if err != nil {
			parseErrors = append(parseErrors, fmt.Sprintf("%s: %v", reqFile, err))
			continue
		}

		for _, pkg := range packages {
			key := pkg.Name + "@" + pkg.Version
			if !seen[key] {
				seen[key] = true
				allPackages = append(allPackages, pkg)
			}
		}
	}

	// If no packages were parsed and there were errors, report failure
	if len(allPackages) == 0 && len(parseErrors) > 0 {
		return &ecosystem.ScanResult{
			Ecosystem: "pip",
			Status:    ecosystem.ScanStatusFailed,
			Errors:    parseErrors,
		}, nil
	}

	// Query OSV for vulnerabilities
	findings, err := ecosystem.DefaultOSVClient.CheckPackages(ctx, allPackages)
	if err != nil {
		// Vulnerability check failure is a critical error - cannot guarantee safety
		return nil, fmt.Errorf("vulnerability check failed: %w", err)
	}

	result := &ecosystem.ScanResult{
		Ecosystem:       "pip", // Must match plugin Name for registry lookups
		PackagesScanned: len(allPackages),
		Findings:        findings,
		Status:          ecosystem.ScanStatusSuccess,
	}

	// Include parse errors as warnings if some files failed but we got packages from others
	if len(parseErrors) > 0 {
		result.Errors = parseErrors
		result.Status = ecosystem.ScanStatusPartial
	}

	return result, nil
}

// GetFix returns the pip command to fix a vulnerability.
func (p *Plugin) GetFix(ctx context.Context, pkg ecosystem.Package, vuln ecosystem.Vulnerability) (*ecosystem.FixAction, error) {
	if vuln.FixVersion == "" {
		return &ecosystem.FixAction{
			Type:        "workaround",
			Description: fmt.Sprintf("No fix available for %s. Consider removing or replacing the package.", vuln.ID),
		}, nil
	}

	return &ecosystem.FixAction{
		Type:          "upgrade",
		Command:       fmt.Sprintf("pip install %s==%s", pkg.Name, vuln.FixVersion),
		Description:   fmt.Sprintf("Upgrade %s from %s to %s", pkg.Name, pkg.Version, vuln.FixVersion),
		TargetVersion: vuln.FixVersion,
	}, nil
}

// NativeAudit runs pip-audit if available.
func (p *Plugin) NativeAudit(ctx context.Context, path string) (*ecosystem.ScanResult, error) {
	// Check if pip-audit is available
	if _, err := exec.LookPath("pip-audit"); err != nil {
		return nil, fmt.Errorf("pip-audit not installed (pip install pip-audit)")
	}

	cmd := exec.CommandContext(ctx, "pip-audit", "--format=json", "-r", "requirements.txt")
	cmd.Dir = path

	output, err := cmd.Output()
	if err != nil {
		if len(output) == 0 {
			return nil, fmt.Errorf("pip-audit failed: %w", err)
		}
	}

	// TODO: Parse pip-audit JSON output
	// For now, fall back to OSV scan
	return p.Scan(ctx, path)
}

// findRequirementsFiles finds all requirements files in a project.
func findRequirementsFiles(path string) []string {
	var files []string

	// Check common patterns
	patterns := []string{
		"requirements.txt",
		"requirements-dev.txt",
		"requirements-prod.txt",
		"requirements-test.txt",
	}

	for _, pattern := range patterns {
		fullPath := filepath.Join(path, pattern)
		if _, err := os.Stat(fullPath); err == nil {
			files = append(files, fullPath)
		}
	}

	// Check requirements directory
	reqDir := filepath.Join(path, "requirements")
	if info, err := os.Stat(reqDir); err == nil && info.IsDir() {
		_ = filepath.Walk(reqDir, func(p string, info os.FileInfo, err error) error {
			if err == nil && !info.IsDir() && strings.HasSuffix(p, ".txt") {
				files = append(files, p)
			}
			return nil
		})
	}

	return files
}

// Package names can include dots (zope.interface), underscores, and hyphens.
var requirementsLineRegex = regexp.MustCompile(`^([a-zA-Z0-9._-]+)\s*[=<>!~]+\s*([0-9][^\s;#]*)`)

// parseRequirements parses a requirements.txt file.
func parseRequirements(path string) ([]ecosystem.Package, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer func() { _ = file.Close() }()

	var packages []ecosystem.Package

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip comments and empty lines
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
			continue
		}

		matches := requirementsLineRegex.FindStringSubmatch(line)
		if matches == nil {
			continue
		}

		name := strings.ToLower(matches[1]) // PyPI normalizes to lowercase
		version := matches[2]

		packages = append(packages, ecosystem.Package{
			Name:      name,
			Version:   version,
			Ecosystem: "PyPI",
			Source:    path,
		})
	}

	return packages, scanner.Err()
}
