// Package ecosystem provides a pluggable interface for different package ecosystems.
// Each ecosystem (npm, go, pip, brew, debian, etc.) implements the Plugin interface
// to provide scanning, vulnerability detection, and remediation capabilities.
package ecosystem

import "context"

// Package represents a software package in any ecosystem.
type Package struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Ecosystem string `json:"ecosystem"`

	// Optional metadata
	Source   string `json:"source,omitempty"`   // Lock file path, system package db, etc.
	Direct   bool   `json:"direct,omitempty"`   // Direct vs transitive dependency
	Checksum string `json:"checksum,omitempty"` // For integrity verification
}

// Vulnerability represents a security vulnerability affecting a package.
type Vulnerability struct {
	ID         string   `json:"id"`                    // CVE-2021-23337, GHSA-xxx, etc.
	Aliases    []string `json:"aliases,omitempty"`     // Alternative IDs
	Severity   string   `json:"severity"`              // CRITICAL, HIGH, MEDIUM, LOW
	CVSSScore  *float64 `json:"cvss_score,omitempty"`  // Numeric score if available
	Summary    string   `json:"summary"`               // Short description
	Details    string   `json:"details,omitempty"`     // Full description
	FixVersion string   `json:"fix_version,omitempty"` // Version that fixes this
	References []string `json:"references,omitempty"`  // URLs for more info
}

// ScanStatus indicates the outcome of a scan operation.
type ScanStatus string

const (
	// ScanStatusSuccess indicates the scan completed successfully.
	ScanStatusSuccess ScanStatus = "success"
	// ScanStatusPartial indicates the scan completed but with some errors.
	ScanStatusPartial ScanStatus = "partial"
	// ScanStatusFailed indicates the scan failed completely.
	ScanStatusFailed ScanStatus = "failed"
)

// ScanResult contains packages and their vulnerabilities.
type ScanResult struct {
	Ecosystem       string          `json:"ecosystem"`
	PackagesScanned int             `json:"packages_scanned"`
	Findings        []Finding       `json:"findings"`
	Errors          []string        `json:"errors,omitempty"`
	Status          ScanStatus      `json:"status"`
}

// Success returns true if the scan completed without critical errors.
// A scan with findings but no errors is considered successful.
func (r *ScanResult) Success() bool {
	return r.Status == ScanStatusSuccess || r.Status == ScanStatusPartial
}

// Failed returns true if the scan failed completely.
func (r *ScanResult) Failed() bool {
	return r.Status == ScanStatusFailed
}

// HasErrors returns true if the scan encountered any errors.
func (r *ScanResult) HasErrors() bool {
	return len(r.Errors) > 0
}

// Finding links a package to its vulnerabilities.
type Finding struct {
	Package         Package         `json:"package"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
}

// FixAction describes how to remediate a vulnerability.
type FixAction struct {
	Type        string `json:"type"`                  // "upgrade", "patch", "remove", "workaround"
	Command     string `json:"command,omitempty"`     // Shell command to execute
	Description string `json:"description,omitempty"` // Human-readable explanation
	TargetVersion string `json:"target_version,omitempty"` // Version to upgrade to
	Breaking    bool   `json:"breaking,omitempty"`    // Potentially breaking change?
}

// Plugin is the interface that all ecosystem plugins must implement.
type Plugin interface {
	// Info returns metadata about the plugin.
	Info() PluginInfo

	// Detect checks if this plugin can handle the given path.
	// Returns true if lock files, manifests, or other indicators are found.
	Detect(ctx context.Context, path string) bool

	// Scan enumerates packages and checks for vulnerabilities.
	Scan(ctx context.Context, path string) (*ScanResult, error)

	// GetFix returns remediation actions for a specific vulnerability.
	// The package parameter provides context (current version, ecosystem).
	GetFix(ctx context.Context, pkg Package, vuln Vulnerability) (*FixAction, error)
}

// PluginInfo contains metadata about a plugin.
type PluginInfo struct {
	// Name is the ecosystem identifier (e.g., "npm", "go", "debian").
	Name string

	// DisplayName is human-readable (e.g., "Node.js (npm)").
	DisplayName string

	// Description explains what this plugin handles.
	Description string

	// FilePatterns lists files this plugin looks for (e.g., "package-lock.json").
	FilePatterns []string

	// Priority determines order when multiple plugins match (higher = first).
	Priority int
}

// PluginWithNativeAudit is an optional interface for plugins that have
// native audit tools (npm audit, cargo audit, etc.).
type PluginWithNativeAudit interface {
	Plugin

	// NativeAudit runs the ecosystem's native audit command.
	// Returns findings directly from the native tool.
	NativeAudit(ctx context.Context, path string) (*ScanResult, error)
}

// PluginWithAdvisorySource is an optional interface for plugins that
// can query specific advisory databases.
type PluginWithAdvisorySource interface {
	Plugin

	// AdvisorySources returns the advisory databases this plugin uses.
	AdvisorySources() []string

	// CheckAdvisory queries a specific advisory database for a package.
	CheckAdvisory(ctx context.Context, source string, pkg Package) ([]Vulnerability, error)
}
