// Package npm provides the npm/Node.js ecosystem plugin.
package npm

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/emphereio/ovrse/pkg/ecosystem"
	"github.com/emphereio/ovrse/pkg/logging"
)

func init() {
	_ = ecosystem.Register(&Plugin{})
}

// Plugin implements the npm ecosystem.
type Plugin struct{}

// Info returns plugin metadata.
func (p *Plugin) Info() ecosystem.PluginInfo {
	return ecosystem.PluginInfo{
		Name:        "npm",
		DisplayName: "Node.js (npm)",
		Description: "Scans package-lock.json for npm/Node.js vulnerabilities",
		FilePatterns: []string{
			"package-lock.json",
			"package.json",
		},
		Priority: 100,
	}
}

// Detect checks if this is an npm project with a scannable lock file.
func (p *Plugin) Detect(ctx context.Context, path string) bool {
	// Only detect if package-lock.json exists (required for scanning)
	lockFile := filepath.Join(path, "package-lock.json")
	_, err := os.Stat(lockFile)
	return err == nil
}

// Scan parses package-lock.json and checks for vulnerabilities.
func (p *Plugin) Scan(ctx context.Context, path string) (*ecosystem.ScanResult, error) {
	logger := logging.WithComponent("ecosystem.npm")
	logger.Debug().Str("path", path).Msg("scanning npm project")

	lockFile := filepath.Join(path, "package-lock.json")
	packages, err := parseLockFile(lockFile)
	if err != nil {
		logger.Error().Err(err).Str("lockfile", lockFile).Msg("failed to parse lock file")
		return nil, fmt.Errorf("failed to parse lock file: %w", err)
	}

	// Query OSV for vulnerabilities
	findings, err := ecosystem.DefaultOSVClient.CheckPackages(ctx, packages)
	if err != nil {
		// Vulnerability check failure is a critical error - cannot guarantee safety
		return nil, fmt.Errorf("vulnerability check failed: %w", err)
	}

	return &ecosystem.ScanResult{
		Ecosystem:       "npm",
		PackagesScanned: len(packages),
		Findings:        findings,
		Status:          ecosystem.ScanStatusSuccess,
	}, nil
}

// GetFix returns the npm command to fix a vulnerability.
func (p *Plugin) GetFix(ctx context.Context, pkg ecosystem.Package, vuln ecosystem.Vulnerability) (*ecosystem.FixAction, error) {
	if vuln.FixVersion == "" {
		return &ecosystem.FixAction{
			Type:        "workaround",
			Description: fmt.Sprintf("No fix available for %s. Consider removing or replacing the package.", vuln.ID),
		}, nil
	}

	return &ecosystem.FixAction{
		Type:          "upgrade",
		Command:       fmt.Sprintf("npm install %s@%s", pkg.Name, vuln.FixVersion),
		Description:   fmt.Sprintf("Upgrade %s from %s to %s", pkg.Name, pkg.Version, vuln.FixVersion),
		TargetVersion: vuln.FixVersion,
	}, nil
}

// NativeAudit runs npm audit and returns findings.
func (p *Plugin) NativeAudit(ctx context.Context, path string) (*ecosystem.ScanResult, error) {
	cmd := exec.CommandContext(ctx, "npm", "audit", "--json")
	cmd.Dir = path

	output, err := cmd.Output()
	if err != nil {
		// npm audit returns non-zero exit code when vulnerabilities found
		// Check if we got JSON output anyway
		if len(output) == 0 {
			return nil, fmt.Errorf("npm audit failed: %w", err)
		}
	}

	return parseNpmAuditOutput(output)
}

// parseLockFile parses package-lock.json and returns packages.
func parseLockFile(path string) ([]ecosystem.Package, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	var lockFile npmLockFile
	if err := json.Unmarshal(data, &lockFile); err != nil {
		return nil, fmt.Errorf("failed to parse JSON: %w", err)
	}

	var packages []ecosystem.Package
	seen := make(map[string]bool)

	// v2/v3 format: packages field
	for key, pkg := range lockFile.Packages {
		if key == "" {
			continue // Skip root package
		}

		name := pkg.Name
		if name == "" {
			// Extract name from path: "node_modules/lodash" -> "lodash"
			parts := strings.Split(key, "node_modules/")
			if len(parts) > 1 {
				name = parts[len(parts)-1]
			} else {
				name = key
			}
		}

		version := pkg.Version
		if version == "" {
			continue
		}

		pkgKey := name + "@" + version
		if seen[pkgKey] {
			continue
		}
		seen[pkgKey] = true

		packages = append(packages, ecosystem.Package{
			Name:      name,
			Version:   version,
			Ecosystem: "npm",
			Source:    path,
		})
	}

	// v1 format fallback: dependencies field
	if len(packages) == 0 {
		for name, dep := range lockFile.Dependencies {
			if dep.Version == "" {
				continue
			}
			packages = append(packages, ecosystem.Package{
				Name:      name,
				Version:   dep.Version,
				Ecosystem: "npm",
				Source:    path,
			})
		}
	}

	return packages, nil
}

// parseNpmAuditOutput parses npm audit --json output.
func parseNpmAuditOutput(data []byte) (*ecosystem.ScanResult, error) {
	var audit npmAuditOutput
	if err := json.Unmarshal(data, &audit); err != nil {
		return nil, fmt.Errorf("failed to parse npm audit output: %w", err)
	}

	var findings []ecosystem.Finding

	for _, vuln := range audit.Vulnerabilities {
		severity := strings.ToUpper(vuln.Severity)

		// Extract advisory info from Via array safely
		var advisoryID, advisoryTitle string
		if len(vuln.Via) > 0 {
			advisoryID = vuln.Via[0].Source
			advisoryTitle = vuln.Via[0].Title
		} else {
			// Fallback when Via is empty
			advisoryID = fmt.Sprintf("npm-%s", vuln.Name)
			advisoryTitle = fmt.Sprintf("Vulnerability in %s", vuln.Name)
		}

		finding := ecosystem.Finding{
			Package: ecosystem.Package{
				Name:      vuln.Name,
				Version:   vuln.Range,
				Ecosystem: "npm",
			},
			Vulnerabilities: []ecosystem.Vulnerability{
				{
					ID:         advisoryID,
					Severity:   severity,
					Summary:    advisoryTitle,
					FixVersion: vuln.FixAvailable.Version,
				},
			},
		}
		findings = append(findings, finding)
	}

	return &ecosystem.ScanResult{
		Ecosystem:       "npm",
		PackagesScanned: audit.Metadata.TotalDependencies,
		Findings:        findings,
		Status:          ecosystem.ScanStatusSuccess,
	}, nil
}

// Lock file types
type npmLockFile struct {
	Packages     map[string]npmPackage    `json:"packages"`
	Dependencies map[string]npmDependency `json:"dependencies"`
}

type npmPackage struct {
	Version string `json:"version"`
	Name    string `json:"name,omitempty"`
}

type npmDependency struct {
	Version string `json:"version"`
}

// npm audit types
type npmAuditOutput struct {
	Vulnerabilities map[string]npmVuln `json:"vulnerabilities"`
	Metadata        npmMetadata        `json:"metadata"`
}

type npmVuln struct {
	Name         string       `json:"name"`
	Severity     string       `json:"severity"`
	Range        string       `json:"range"`
	Via          []npmVia     `json:"via"`
	FixAvailable npmFix       `json:"fixAvailable"`
}

type npmVia struct {
	Source string `json:"source"`
	Title  string `json:"title"`
}

type npmFix struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type npmMetadata struct {
	TotalDependencies int `json:"totalDependencies"`
}
