// Package store provides SQLite storage for Overseer's vulnerability tracking.
package store

import "time"

// Project represents a monitored project directory.
type Project struct {
	ID            int64      `json:"id"`
	Path          string     `json:"path"`
	Name          string     `json:"name,omitempty"`
	Ecosystem     string     `json:"ecosystem,omitempty"` // npm, go, pip, etc.
	AddedAt       time.Time  `json:"added_at"`
	LastScannedAt *time.Time `json:"last_scanned_at,omitempty"`
}

// Package represents a detected package in a project.
type Package struct {
	ID        int64  `json:"id"`
	ProjectID int64  `json:"project_id"`
	Name      string `json:"name"`
	Version   string `json:"version"`
	Ecosystem string `json:"ecosystem"` // npm, go, pip, cargo, etc.
	LockFile  string `json:"lock_file,omitempty"`
}

// Vulnerability represents a detected vulnerability in a package.
type Vulnerability struct {
	ID          int64      `json:"id"`
	PackageID   int64      `json:"package_id"`
	CVEID       string     `json:"cve_id"`
	Severity    string     `json:"severity,omitempty"`   // CRITICAL, HIGH, MEDIUM, LOW
	CVSSScore   *float64   `json:"cvss_score,omitempty"` // nil if unknown
	Summary     string     `json:"summary,omitempty"`
	FixVersion  string     `json:"fix_version,omitempty"`
	DetectedAt  time.Time  `json:"detected_at"`
	DismissedAt *time.Time `json:"dismissed_at,omitempty"`
}

// Scan represents a scan history entry.
type Scan struct {
	ID              int64      `json:"id"`
	ProjectID       int64      `json:"project_id"`
	StartedAt       time.Time  `json:"started_at"`
	CompletedAt     *time.Time `json:"completed_at,omitempty"`
	PackagesScanned int        `json:"packages_scanned"`
	VulnsFound      int        `json:"vulns_found"`
	Status          string     `json:"status"` // running, completed, failed
}

// ScanStatus constants for scan state tracking.
const (
	ScanStatusRunning   = "running"
	ScanStatusCompleted = "completed"
	ScanStatusFailed    = "failed"
)

// Severity constants for vulnerability classification.
const (
	SeverityCritical = "CRITICAL"
	SeverityHigh     = "HIGH"
	SeverityMedium   = "MEDIUM"
	SeverityLow      = "LOW"
	SeverityUnknown  = "UNKNOWN"
)

// VulnFilter provides filtering options for vulnerability queries.
type VulnFilter struct {
	ProjectID   *int64   // Filter by specific project
	ProjectPath string   // Filter by project path
	Severity    []string // Filter by severity levels
	CVEID       string   // Filter by specific CVE
	Dismissed   *bool    // Filter dismissed status (nil = all, true = dismissed only, false = active only)
	Limit       int      // Max results (0 = unlimited)
}

// VulnResult represents a vulnerability with its associated package and project info.
type VulnResult struct {
	Vulnerability
	PackageName    string `json:"package_name"`
	PackageVersion string `json:"package_version"`
	PackageEco     string `json:"package_ecosystem"`
	ProjectPath    string `json:"project_path"`
	ProjectName    string `json:"project_name,omitempty"`
}

// ProjectSummary provides a summary of vulnerabilities in a project.
type ProjectSummary struct {
	Project
	TotalPackages int            `json:"total_packages"`
	TotalVulns    int            `json:"total_vulns"`
	BySeverity    map[string]int `json:"by_severity"` // severity -> count
}
