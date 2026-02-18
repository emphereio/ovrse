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
// Matches intel-engine _format_summary() output.
type AnalyzeCVEResponse struct {
	// Action-oriented fields (primary decision)
	Action          string   `json:"action"`                     // fix_now, fix_later, already_fixed, not_affected, no_fix, needs_review
	ActionReason    string   `json:"action_reason,omitempty"`    // Explanation for action
	CanAutoFix      bool     `json:"can_auto_fix"`               // True if safe to auto-apply
	AutoFixBlockers []string `json:"auto_fix_blockers,omitempty"` // Reasons blocking auto-fix
	Fix             *FixInfo `json:"fix,omitempty"`              // Fix command and details
	VerifyCommand   *string  `json:"verify_command,omitempty"`   // Command to verify fix worked
	FeedbackHint    *FeedbackHint `json:"feedback_hint,omitempty"` // Present when feedback is valuable

	// Version status (if current_version was provided)
	VersionStatus       *string `json:"version_status,omitempty"`        // not_affected, vulnerable, fixed
	VersionStatusReason *string `json:"version_status_reason,omitempty"` // Explanation

	// Risk glance (compact risk summary)
	Risk *RiskGlance `json:"risk,omitempty"`

	// Core identifiers
	CVEID            string             `json:"cve_id"`
	PackageName      *string            `json:"package_name,omitempty"`
	AffectedPackages []AffectedPackage  `json:"affected_packages,omitempty"`
	Ecosystem        *string            `json:"ecosystem,omitempty"`

	// Verdict (original decision)
	Verdict string  `json:"verdict,omitempty"` // patch_immediately, patch_with_caution, defer, etc.
	TLDR    *string `json:"tldr,omitempty"`    // One-line summary for quick decision

	// Upgrade path
	UpgradePath *string `json:"upgrade_path,omitempty"` // e.g., "4.17.15 → 4.17.21"
	FixVersion  *string `json:"fix_version,omitempty"`

	// Exploitability signals
	KEVListed      *bool    `json:"kev_listed,omitempty"`      // nil = not analyzed
	EPSSScore      *float64 `json:"epss_score,omitempty"`
	EPSSPercentile *float64 `json:"epss_percentile,omitempty"`
	CVSSScore      *float64 `json:"cvss_score,omitempty"`
	EffectiveRisk  *string  `json:"effective_risk,omitempty"`  // critical, high, medium, low
	RecommendedSLA *string  `json:"recommended_sla,omitempty"` // immediate, 24h, 7d, 30d

	// Safety signals (breaking changes + stability)
	HasBreakingChanges bool             `json:"has_breaking_changes"`
	BreakingChanges    []string         `json:"breaking_changes,omitempty"` // Descriptions
	Stability          *string          `json:"stability,omitempty"`        // "90% stable, 5% regret"
	RegretIndex        *float64         `json:"regret_index,omitempty"`
	RequiresRestart    *bool            `json:"requires_restart,omitempty"`
	RestartType        *string          `json:"restart_type,omitempty"` // service, reboot

	// Transitive impact
	TransitiveImpact      *string `json:"transitive_impact,omitempty"`      // Human-readable
	TransitiveNetPositive *bool   `json:"transitive_net_positive,omitempty"`

	// Remediation commands
	RemediationCommands []RemediationCommand `json:"remediation_commands,omitempty"`
	ActionItems         []string             `json:"action_items,omitempty"`

	// Environment flags
	RemediationType *string  `json:"remediation_type,omitempty"`
	RequiresGUI     *bool    `json:"requires_gui,omitempty"`
	RequiresReboot  *bool    `json:"requires_reboot,omitempty"`
	AppliesTo       *string  `json:"applies_to,omitempty"`

	// Summaries
	ExecutiveSummary *string `json:"executive_summary,omitempty"`
	EngineerSummary  *string `json:"engineer_summary,omitempty"`

	// Decision support
	DeferSafe *bool    `json:"defer_safe,omitempty"`
	Caveats   []string `json:"caveats,omitempty"`

	// Metadata
	Cached bool `json:"cached"`

	// Error fields (for error responses)
	Error     *string `json:"error,omitempty"`
	ErrorCode *string `json:"error_code,omitempty"`
}

// FixInfo contains the fix command and related information.
type FixInfo struct {
	Command     string  `json:"command"`               // Ready-to-run command
	Tool        *string `json:"tool,omitempty"`        // npm, pip, go, etc.
	Package     *string `json:"package,omitempty"`     // Package name
	FromVersion *string `json:"from_version,omitempty"` // Current version
	ToVersion   *string `json:"to_version,omitempty"`   // Target fix version
}

// RiskGlance is a compact risk summary for quick decision-making.
type RiskGlance struct {
	KEV            *bool `json:"kev,omitempty"`             // nil = not analyzed
	EPSS           *float64 `json:"epss,omitempty"`         // EPSS score
	BreakingCount  int   `json:"breaking_count"`            // Number of breaking changes
	Stable         *bool `json:"stable,omitempty"`          // nil = not analyzed
	TransitiveSafe *bool `json:"transitive_safe,omitempty"` // nil = not analyzed
}

// AffectedPackage represents a package affected by the CVE.
type AffectedPackage struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

// RemediationCommand is a structured command for remediation.
type RemediationCommand struct {
	Order        int                  `json:"order"`
	Action       string               `json:"action"`
	Command      string               `json:"command"`
	Category     string               `json:"category,omitempty"`
	Alternatives []CommandAlternative `json:"alternatives,omitempty"`
}

// CommandAlternative is an alternative command option.
type CommandAlternative struct {
	Label   string `json:"label"`
	Command string `json:"command"`
}

// FeedbackHint indicates when feedback should be reported.
type FeedbackHint struct {
	Tool    string          `json:"tool"`    // "report_remediation_outcome"
	When    string          `json:"when"`    // "after attempting remediation"
	Prefill FeedbackPrefill `json:"prefill"`
}

// FeedbackPrefill contains default values for feedback reporting.
type FeedbackPrefill struct {
	CVEID       string `json:"cve_id"`
	PackageName string `json:"package_name,omitempty"`
	Ecosystem   string `json:"ecosystem,omitempty"`
	FromVersion string `json:"from_version,omitempty"`
	ToVersion   string `json:"to_version,omitempty"`
}

// VerdictResponse is the quick verdict response.
// Matches intel-engine _get_cve_verdict_impl() output.
type VerdictResponse struct {
	CVEID         string  `json:"cve_id"`
	Verdict       string  `json:"verdict"` // patch_immediately, patch_with_caution, defer, not_analyzed, error
	Confidence    *float64 `json:"confidence,omitempty"`
	KEVListed     *bool   `json:"kev_listed,omitempty"`
	EffectiveRisk *string `json:"effective_risk,omitempty"`
	PackageName   *string `json:"package_name,omitempty"`
	FixVersion    *string `json:"fix_version,omitempty"`
	Cached        bool    `json:"cached"`
	ExpiresAt     *string `json:"expires_at,omitempty"`
	NeedsRefresh  *bool   `json:"needs_refresh,omitempty"`
	TLDR          *string `json:"tldr,omitempty"`
	Message       *string `json:"message,omitempty"` // For not_analyzed status
	Error         *string `json:"error,omitempty"`
}

// BatchTriageRequest is the request for batch CVE triage.
type BatchTriageRequest struct {
	CVEIDs []string `json:"cve_ids"`
}

// BatchTriageResponse is the batch triage response.
// Matches intel-engine _batch_triage_impl() output.
type BatchTriageResponse struct {
	Results []VerdictResponse `json:"results"` // Sorted by risk
	Summary TriageSummary     `json:"summary"`
	Error   *string           `json:"error,omitempty"`
}

// TriageSummary summarizes the batch triage results.
type TriageSummary struct {
	Total            int `json:"total"`
	PatchImmediately int `json:"patch_immediately"`
	PatchWithCaution int `json:"patch_with_caution"`
	KEVListed        int `json:"kev_listed"`
	NotAnalyzed      int `json:"not_analyzed"`
	Errors           int `json:"errors"`
}

// CheckAffectedRequest checks if a specific version is affected.
type CheckAffectedRequest struct {
	CVEID          string `json:"cve_id"`
	PackageName    string `json:"package_name"`
	CurrentVersion string `json:"current_version"`
	Ecosystem      string `json:"ecosystem"`
}

// CheckAffectedResponse is the affected check response.
// Matches intel-engine _check_if_affected_impl() output.
type CheckAffectedResponse struct {
	CVEID               string  `json:"cve_id"`
	PackageName         string  `json:"package_name"`
	CurrentVersion      string  `json:"current_version"`
	Ecosystem           string  `json:"ecosystem"`
	Status              string  `json:"status"` // not_affected, vulnerable, fixed, unknown, error
	Explanation         *string `json:"explanation,omitempty"`
	FixVersion          *string `json:"fix_version,omitempty"`
	IntroducedVersion   *string `json:"introduced_version,omitempty"`
	LastAffectedVersion *string `json:"last_affected_version,omitempty"`
	Action              string  `json:"action,omitempty"`  // none_required, upgrade_recommended
	Message             *string `json:"message,omitempty"`
	Cached              bool    `json:"cached"`
	Error               *string `json:"error,omitempty"`
	ErrorCode           *string `json:"error_code,omitempty"`
}

// ReportOutcomeRequest reports a remediation outcome.
// Note: The endpoint is /v1/feedback (not report-outcome).
type ReportOutcomeRequest struct {
	CVEID                 string                 `json:"cve_id"`
	PackageName           string                 `json:"package_name"`
	Ecosystem             string                 `json:"ecosystem"`
	FromVersion           string                 `json:"from_version"`
	ToVersion             string                 `json:"to_version"`
	Outcome               string                 `json:"outcome"` // success, failure, partial
	FailureReason         *string                `json:"failure_reason,omitempty"`
	ErrorMessage          *string                `json:"error_message,omitempty"`
	BreakingChangeDetails *string                `json:"breaking_change_details,omitempty"`
	AlternativeVersion    *string                `json:"alternative_version,omitempty"`
	Environment           map[string]interface{} `json:"environment,omitempty"`
}

// ReportOutcomeResponse is the outcome report response.
// Matches intel-engine _report_remediation_outcome_impl() output.
type ReportOutcomeResponse struct {
	Success     bool    `json:"success"`
	FeedbackID  *string `json:"feedback_id,omitempty"`
	Message     *string `json:"message,omitempty"`
	CVEID       *string `json:"cve_id,omitempty"`
	PackageName *string `json:"package_name,omitempty"`
	Outcome     *string `json:"outcome,omitempty"`
	Error       *string `json:"error,omitempty"`
	ErrorCode   *string `json:"error_code,omitempty"`
}

// APIError represents an error response from the API.
type APIError struct {
	Error   string `json:"error"`
	Message string `json:"message,omitempty"`
	Detail  string `json:"detail,omitempty"`
}
