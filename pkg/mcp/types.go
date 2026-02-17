// Package mcp provides an MCP server for exposing Overseer functionality.
package mcp

// VulnerabilityInfo represents a vulnerability for MCP responses.
type VulnerabilityInfo struct {
	CVEID       string   `json:"cve_id"`
	PackageName string   `json:"package_name"`
	Version     string   `json:"version"`
	Ecosystem   string   `json:"ecosystem"`
	Severity    string   `json:"severity"`
	CVSSScore   *float64 `json:"cvss_score,omitempty"`
	Summary     string   `json:"summary,omitempty"`
	FixVersion  string   `json:"fix_version,omitempty"`
	ProjectPath string   `json:"project_path"`
	DetectedAt  string   `json:"detected_at"`
}

// ProjectInfo represents a monitored project for MCP responses.
type ProjectInfo struct {
	Path        string `json:"path"`
	Name        string `json:"name,omitempty"`
	Ecosystem   string `json:"ecosystem,omitempty"`
	LastScanned string `json:"last_scanned,omitempty"`
	VulnCount   int    `json:"vuln_count"`
}

// ScanSummary represents scan results for MCP responses.
type ScanSummary struct {
	ProjectPath     string         `json:"project_path"`
	PackagesScanned int            `json:"packages_scanned"`
	VulnsFound      int            `json:"vulns_found"`
	BySeverity      map[string]int `json:"by_severity"`
}

// ListVulnsArgs are arguments for list_vulnerabilities tool.
type ListVulnsArgs struct {
	Severity string `json:"severity,omitempty"`
	Project  string `json:"project,omitempty"`
	Limit    int    `json:"limit,omitempty"`
}

// ListProjectsArgs are arguments for list_projects tool.
type ListProjectsArgs struct {
	Limit int `json:"limit,omitempty"`
}

// GetProjectStatusArgs are arguments for get_project_status tool.
type GetProjectStatusArgs struct {
	Path string `json:"path"`
}

// ScanNowArgs are arguments for scan_now tool.
type ScanNowArgs struct {
	Path string `json:"path"`
}

// AnalyzeCVEArgs are arguments for analyze_cve tool.
type AnalyzeCVEArgs struct {
	CVEID          string `json:"cve_id"`
	PackageName    string `json:"package_name,omitempty"`
	CurrentVersion string `json:"current_version,omitempty"`
	Ecosystem      string `json:"ecosystem,omitempty"`
	OutputFormat   string `json:"output_format,omitempty"`
}

// GetCVEVerdictArgs are arguments for get_cve_verdict tool.
type GetCVEVerdictArgs struct {
	CVEID string `json:"cve_id"`
}

// BatchTriageArgs are arguments for batch_triage tool.
type BatchTriageArgs struct {
	CVEIDs []string `json:"cve_ids"`
}

// CheckIfAffectedArgs are arguments for check_if_affected tool.
type CheckIfAffectedArgs struct {
	CVEID          string `json:"cve_id"`
	PackageName    string `json:"package_name"`
	CurrentVersion string `json:"current_version"`
	Ecosystem      string `json:"ecosystem"`
}

// ReportOutcomeArgs are arguments for report_remediation_outcome tool.
type ReportOutcomeArgs struct {
	CVEID                 string                 `json:"cve_id"`
	PackageName           string                 `json:"package_name"`
	Ecosystem             string                 `json:"ecosystem"`
	FromVersion           string                 `json:"from_version"`
	ToVersion             string                 `json:"to_version"`
	Outcome               string                 `json:"outcome"`
	FailureReason         string                 `json:"failure_reason,omitempty"`
	ErrorMessage          string                 `json:"error_message,omitempty"`
	BreakingChangeDetails string                 `json:"breaking_change_details,omitempty"`
	AlternativeVersion    string                 `json:"alternative_version,omitempty"`
	Environment           map[string]interface{} `json:"environment,omitempty"`
}
