// Package intel provides a client for the Intel-engine remediation API.
package intel

// AnalyzeCVERequest is the request for CVE analysis.
type AnalyzeCVERequest struct {
	CVEID          string  `json:"cve_id"`
	PackageName    *string `json:"package_name,omitempty"`
	CurrentVersion *string `json:"current_version,omitempty"`
	Ecosystem      *string `json:"ecosystem,omitempty"`
	OutputFormat   string  `json:"output_format,omitempty"` // "summary" or "full"
}

// AnalyzeCVEResponse is the response from CVE analysis.
type AnalyzeCVEResponse struct {
	Action           string            `json:"action"` // fix_now, fix_later, already_fixed, not_affected, no_fix, needs_review
	CanAutoFix       bool              `json:"can_auto_fix"`
	AutoFixBlockers  []string          `json:"auto_fix_blockers,omitempty"`
	Fix              *FixInfo          `json:"fix,omitempty"`
	VerifyCommand    *string           `json:"verify_command,omitempty"`
	FeedbackHint     *FeedbackHint     `json:"feedback_hint,omitempty"`
	AffectedPackages []string          `json:"affected_packages,omitempty"`
	VersionStatus    *string           `json:"version_status,omitempty"`
	Stability        *string           `json:"stability,omitempty"`
	RegretIndex      *float64          `json:"regret_index,omitempty"`
	KEVListed        *bool             `json:"kev_listed,omitempty"`
	EPSS             *EPSSInfo         `json:"epss,omitempty"`
	Summary          *string           `json:"summary,omitempty"`
	BreakingChanges  []BreakingChange  `json:"breaking_changes,omitempty"`
}

// FixInfo contains the fix command and related information.
type FixInfo struct {
	Command     string  `json:"command"`
	FixVersion  string  `json:"fix_version,omitempty"`
	Confidence  *string `json:"confidence,omitempty"`
}

// FeedbackHint indicates when feedback should be reported.
type FeedbackHint struct {
	Prefill FeedbackPrefill `json:"prefill"`
}

// FeedbackPrefill contains default values for feedback reporting.
type FeedbackPrefill struct {
	CVEID       string `json:"cve_id"`
	PackageName string `json:"package_name"`
	Ecosystem   string `json:"ecosystem"`
	FromVersion string `json:"from_version"`
	ToVersion   string `json:"to_version"`
}

// EPSSInfo contains EPSS (Exploit Prediction Scoring System) data.
type EPSSInfo struct {
	Score      float64 `json:"score"`
	Percentile float64 `json:"percentile"`
}

// BreakingChange describes a potential breaking change in an upgrade.
type BreakingChange struct {
	Description string  `json:"description"`
	Severity    string  `json:"severity,omitempty"`
	MigrationGuide *string `json:"migration_guide,omitempty"`
}

// VerdictRequest is the request for quick CVE verdict lookup.
type VerdictRequest struct {
	CVEID string `json:"cve_id"`
}

// VerdictResponse is the quick verdict response.
type VerdictResponse struct {
	Verdict   string `json:"verdict"` // patch_immediately, patch_with_caution, defer, not_analyzed, not_applicable
	KEVListed *bool  `json:"kev_listed,omitempty"`
	Cached    bool   `json:"cached"`
}

// BatchTriageRequest is the request for batch CVE triage.
type BatchTriageRequest struct {
	CVEIDs []string `json:"cve_ids"`
}

// BatchTriageResponse is the batch triage response.
type BatchTriageResponse struct {
	Summary TriageSummary   `json:"summary"`
	Results []VerdictResult `json:"results"`
}

// TriageSummary summarizes the batch triage results.
type TriageSummary struct {
	PatchImmediately int `json:"patch_immediately"`
	PatchWithCaution int `json:"patch_with_caution"`
	Defer            int `json:"defer"`
	NotAnalyzed      int `json:"not_analyzed"`
	NotApplicable    int `json:"not_applicable"`
	KEVListed        int `json:"kev_listed"`
}

// VerdictResult is a single verdict in batch triage.
type VerdictResult struct {
	CVEID     string `json:"cve_id"`
	Verdict   string `json:"verdict"`
	KEVListed *bool  `json:"kev_listed,omitempty"`
}

// CheckAffectedRequest checks if a specific version is affected.
type CheckAffectedRequest struct {
	CVEID          string `json:"cve_id"`
	PackageName    string `json:"package_name"`
	CurrentVersion string `json:"current_version"`
	Ecosystem      string `json:"ecosystem"`
}

// CheckAffectedResponse is the affected check response.
type CheckAffectedResponse struct {
	Status     string  `json:"status"` // not_affected, vulnerable, fixed, unknown
	Action     string  `json:"action"` // none_required, upgrade_recommended
	FixVersion *string `json:"fix_version,omitempty"`
}

// ReportOutcomeRequest reports a remediation outcome.
type ReportOutcomeRequest struct {
	CVEID               string                 `json:"cve_id"`
	PackageName         string                 `json:"package_name"`
	Ecosystem           string                 `json:"ecosystem"`
	FromVersion         string                 `json:"from_version"`
	ToVersion           string                 `json:"to_version"`
	Outcome             string                 `json:"outcome"` // success, failure, partial
	FailureReason       *string                `json:"failure_reason,omitempty"`
	ErrorMessage        *string                `json:"error_message,omitempty"`
	BreakingChangeDetails *string              `json:"breaking_change_details,omitempty"`
	AlternativeVersion  *string                `json:"alternative_version,omitempty"`
	Environment         map[string]interface{} `json:"environment,omitempty"`
}

// ReportOutcomeResponse is the outcome report response.
type ReportOutcomeResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message,omitempty"`
}

// APIError represents an error response from the API.
type APIError struct {
	Error   string `json:"error"`
	Message string `json:"message,omitempty"`
	Detail  string `json:"detail,omitempty"`
}
