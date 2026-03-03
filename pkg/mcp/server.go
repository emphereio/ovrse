package mcp

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/emphereio/ovrse/pkg/ecosystem"
	"github.com/emphereio/ovrse/pkg/logging"
	// Import plugins to register them
	_ "github.com/emphereio/ovrse/pkg/ecosystem/golang"
	_ "github.com/emphereio/ovrse/pkg/ecosystem/npm"
	_ "github.com/emphereio/ovrse/pkg/ecosystem/pip"
	"github.com/emphereio/ovrse/pkg/intel"
	"github.com/emphereio/ovrse/pkg/version"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// Server is the MCP server using the plugin system.
type Server struct {
	mcpServer   *server.MCPServer
	intelClient *intel.Client
}

// NewServer creates a new MCP server.
func NewServer(ic *intel.Client) *Server {
	s := &Server{
		intelClient: ic,
	}

	// List available plugins for the instructions
	plugins := ecosystem.List()
	var ecosystems []string
	for _, p := range plugins {
		ecosystems = append(ecosystems, p.Info().DisplayName)
	}

	instructions := fmt.Sprintf(`OVRSE is your security scanning assistant.
Supported ecosystems: %v

Scanning tools:
- scan_project: Scan a project for vulnerabilities (auto-detects ecosystem)
- list_ecosystems: List available ecosystem plugins
- get_fix: Get the fix command for a vulnerability

Remediation tools (Intel-engine API):
- analyze_cve: Get full CVE analysis with fix commands
- get_cve_verdict: Quick priority check
- batch_triage: Triage multiple CVEs by risk
- check_if_affected: Check if a version is affected`, ecosystems)

	s.mcpServer = server.NewMCPServer(
		ServerName,
		Version,
		server.WithToolCapabilities(false),
		server.WithRecovery(),
		server.WithInstructions(instructions),
	)

	s.registerTools()
	return s
}

// MCPServer returns the underlying MCP server.
func (s *Server) MCPServer() *server.MCPServer {
	return s.mcpServer
}

func (s *Server) registerTools() {
	// scan_project - core scanning tool
	s.mcpServer.AddTool(
		mcp.NewTool("scan_project",
			mcp.WithDescription("Scan a project for vulnerabilities. Auto-detects ecosystem (npm, go, pip, etc.) from lock files."),
			mcp.WithString("path", mcp.Required(), mcp.Description("Path to the project directory")),
			mcp.WithString("ecosystem", mcp.Description("Force specific ecosystem (optional)")),
			mcp.WithBoolean("native_audit", mcp.Description("Use native audit tools (e.g. govulncheck for Go) for deeper analysis")),
		),
		s.handleScanProject,
	)

	// list_ecosystems - show available plugins
	s.mcpServer.AddTool(
		mcp.NewTool("list_ecosystems",
			mcp.WithDescription("List all available ecosystem plugins and what they detect."),
		),
		s.handleListEcosystems,
	)

	// get_fix - get fix command for a vuln
	s.mcpServer.AddTool(
		mcp.NewTool("get_fix",
			mcp.WithDescription("Get the fix command for a vulnerability in a package."),
			mcp.WithString("ecosystem", mcp.Required(), mcp.Description("Package ecosystem: npm, go, pip")),
			mcp.WithString("package_name", mcp.Required(), mcp.Description("Package name")),
			mcp.WithString("current_version", mcp.Required(), mcp.Description("Current version")),
			mcp.WithString("fix_version", mcp.Required(), mcp.Description("Version to upgrade to")),
		),
		s.handleGetFix,
	)

	s.registerIntelTools()
}

func (s *Server) handleScanProject(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	logger := logging.WithComponent("mcp")
	logger.Info().Str("tool", "scan_project").Msg("handling request")

	args, err := parseArgs[ScanProjectArgs](request)
	if err != nil {
		logger.Warn().Err(err).Msg("invalid arguments")
		return errorResult(fmt.Errorf("invalid arguments: %w", err)), nil
	}

	if args.Path == "" {
		return errorResult(fmt.Errorf("path is required")), nil
	}

	// Validate and resolve path to prevent path traversal attacks
	absPath, err := filepath.Abs(args.Path)
	if err != nil {
		return errorResult(fmt.Errorf("invalid path: %w", err)), nil
	}

	// Resolve symlinks to get canonical path
	absPath, err = filepath.EvalSymlinks(absPath)
	if err != nil {
		return errorResult(fmt.Errorf("cannot resolve path: %w", err)), nil
	}

	// Check path exists and is a directory
	info, err := os.Stat(absPath)
	if err != nil {
		if os.IsNotExist(err) {
			return errorResult(fmt.Errorf("path not found: %s", absPath)), nil
		}
		return errorResult(fmt.Errorf("cannot access path: %w", err)), nil
	}
	if !info.IsDir() {
		return errorResult(fmt.Errorf("path is not a directory: %s", absPath)), nil
	}

	scanPath := absPath

	var results []*ecosystem.ScanResult

	if args.NativeAudit {
		// Use native audit tools (govulncheck, npm audit, etc.)
		if args.Ecosystem != "" {
			normalizedEco := ecosystem.NormalizeEcosystem(args.Ecosystem)
			plugin, ok := ecosystem.Get(normalizedEco)
			if !ok {
				return errorResult(fmt.Errorf("unknown ecosystem: %s", args.Ecosystem)), nil
			}
			na, ok := plugin.(ecosystem.PluginWithNativeAudit)
			if !ok {
				return errorResult(fmt.Errorf("ecosystem %s does not support native audit", args.Ecosystem)), nil
			}
			result, err := na.NativeAudit(ctx, scanPath)
			if err != nil {
				return errorResult(fmt.Errorf("native audit failed: %w", err)), nil
			}
			results = append(results, result)
		} else {
			var err error
			results, err = ecosystem.NativeAuditAll(ctx, scanPath)
			if err != nil {
				return errorResult(fmt.Errorf("native audit failed: %w", err)), nil
			}
		}
	} else if args.Ecosystem != "" {
		// Use specific plugin (normalize for registry lookup)
		normalizedEco := ecosystem.NormalizeEcosystem(args.Ecosystem)
		plugin, ok := ecosystem.Get(normalizedEco)
		if !ok {
			return errorResult(fmt.Errorf("unknown ecosystem: %s", args.Ecosystem)), nil
		}
		result, err := plugin.Scan(ctx, scanPath)
		if err != nil {
			return errorResult(fmt.Errorf("scan failed: %w", err)), nil
		}
		results = append(results, result)
	} else {
		// Auto-detect and scan all matching ecosystems
		var err error
		results, err = ecosystem.ScanAll(ctx, scanPath)
		if err != nil {
			return errorResult(fmt.Errorf("scan failed: %w", err)), nil
		}
	}

	// Build response
	response := ScanResponse{
		Path:    scanPath,
		Results: results,
	}

	// Calculate totals and check for failures
	var failedEcosystems []string
	for _, r := range results {
		response.TotalPackages += r.PackagesScanned
		for _, f := range r.Findings {
			response.TotalVulns += len(f.Vulnerabilities)
		}
		// Track any scan failures
		if r.Failed() {
			failedEcosystems = append(failedEcosystems, r.Ecosystem)
		}
	}

	// Add warnings for partial failures
	if len(failedEcosystems) > 0 && len(failedEcosystems) < len(results) {
		response.Warnings = append(response.Warnings,
			fmt.Sprintf("scan failed for: %s", strings.Join(failedEcosystems, ", ")))
	}

	logger.Info().
		Int("packages", response.TotalPackages).
		Int("vulnerabilities", response.TotalVulns).
		Msg("scan completed")

	return jsonResult(response)
}

func (s *Server) handleListEcosystems(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	plugins := ecosystem.List()

	var infos []ecosystem.PluginInfo
	for _, p := range plugins {
		infos = append(infos, p.Info())
	}

	return jsonResult(infos)
}

func (s *Server) handleGetFix(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args, err := parseArgs[GetFixArgs](request)
	if err != nil {
		return errorResult(fmt.Errorf("invalid arguments: %w", err)), nil
	}

	// Normalize ecosystem (plugins register as "go"/"pip"/"npm", but
	// scan findings may use "Go"/"PyPI" from OSV)
	normalizedEco := ecosystem.NormalizeEcosystem(args.Ecosystem)
	plugin, ok := ecosystem.Get(normalizedEco)
	if !ok {
		return errorResult(fmt.Errorf("unknown ecosystem: %s", args.Ecosystem)), nil
	}

	pkg := ecosystem.Package{
		Name:      args.PackageName,
		Version:   args.CurrentVersion,
		Ecosystem: normalizedEco,
	}

	vuln := ecosystem.Vulnerability{
		FixVersion: args.FixVersion,
	}

	fix, err := plugin.GetFix(ctx, pkg, vuln)
	if err != nil {
		return errorResult(fmt.Errorf("failed to get fix: %w", err)), nil
	}

	return jsonResult(fix)
}

func (s *Server) registerIntelTools() {
	// analyze_cve
	s.mcpServer.AddTool(
		mcp.NewTool("analyze_cve",
			mcp.WithDescription("Get full CVE analysis with fix commands, breaking change warnings, and verification steps. Accepts CVE, GHSA, PYSEC, GO, or RUSTSEC IDs (auto-resolves to CVE)."),
			mcp.WithString("cve_id", mcp.Required(), mcp.Description("Vulnerability ID (CVE-2024-3094, GHSA-xxxx-xxxx-xxxx, PYSEC-2024-1, etc.)")),
			mcp.WithString("package_name", mcp.Description("Package name if known")),
			mcp.WithString("current_version", mcp.Description("Current version installed")),
			mcp.WithString("ecosystem", mcp.Description("Package ecosystem: npm, pypi, maven, go")),
		),
		s.handleAnalyzeCVE,
	)

	// get_cve_verdict
	s.mcpServer.AddTool(
		mcp.NewTool("get_cve_verdict",
			mcp.WithDescription("Quick priority check for a vulnerability. Accepts CVE, GHSA, PYSEC, GO, or RUSTSEC IDs."),
			mcp.WithString("cve_id", mcp.Required(), mcp.Description("Vulnerability ID (auto-resolves GHSA/PYSEC to CVE)")),
		),
		s.handleGetCVEVerdict,
	)

	// batch_triage
	s.mcpServer.AddTool(
		mcp.NewTool("batch_triage",
			mcp.WithDescription("Triage multiple vulnerabilities at once. Returns risk-sorted verdicts. Accepts CVE, GHSA, PYSEC, GO, or RUSTSEC IDs."),
			mcp.WithArray("cve_ids",
				mcp.Required(),
				mcp.Description("List of vulnerability IDs (max 20, auto-resolves to CVE)"),
				mcp.Items(map[string]interface{}{"type": "string"}),
			),
		),
		s.handleBatchTriage,
	)

	// check_if_affected
	s.mcpServer.AddTool(
		mcp.NewTool("check_if_affected",
			mcp.WithDescription("Quick version check - is this specific version affected? Accepts any OSV vulnerability ID."),
			mcp.WithString("cve_id", mcp.Required(), mcp.Description("Vulnerability ID (CVE, GHSA, PYSEC, GO, RUSTSEC)")),
			mcp.WithString("package_name", mcp.Required(), mcp.Description("Package name")),
			mcp.WithString("current_version", mcp.Required(), mcp.Description("Version to check")),
			mcp.WithString("ecosystem", mcp.Required(), mcp.Description("Package ecosystem")),
		),
		s.handleCheckIfAffected,
	)

	// report_remediation_outcome
	s.mcpServer.AddTool(
		mcp.NewTool("report_remediation_outcome",
			mcp.WithDescription("Report the outcome of a fix attempt. Call when feedback_hint is present in analyze_cve response. Accepts CVE, GHSA, PYSEC, GO, or RUSTSEC IDs."),
			mcp.WithString("cve_id", mcp.Required(), mcp.Description("Vulnerability ID (auto-resolves to CVE)")),
			mcp.WithString("package_name", mcp.Required(), mcp.Description("Package name")),
			mcp.WithString("ecosystem", mcp.Required(), mcp.Description("Package ecosystem (npm, pypi, maven, go)")),
			mcp.WithString("from_version", mcp.Required(), mcp.Description("Version before upgrade")),
			mcp.WithString("to_version", mcp.Required(), mcp.Description("Target version for upgrade")),
			mcp.WithString("outcome", mcp.Required(), mcp.Description("Outcome: success, failure, or partial")),
			mcp.WithString("failure_reason", mcp.Description("Why it failed (required if outcome is not success): command_failed, breaking_change, dependency_conflict, cve_still_detected, wrong_fix_version, not_affected, other")),
			mcp.WithString("error_message", mcp.Description("Error output from failed command")),
			mcp.WithString("breaking_change_details", mcp.Description("What broke after upgrade")),
			mcp.WithString("alternative_version", mcp.Description("Version that worked instead")),
		),
		s.handleReportOutcome,
	)
}

// Intel tool handlers (delegate to intel client)
func (s *Server) handleAnalyzeCVE(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	logger := logging.WithComponent("mcp")
	logger.Info().Str("tool", "analyze_cve").Msg("handling request")

	if s.intelClient == nil {
		return errorResult(fmt.Errorf("intel-engine not configured")), nil
	}

	args, err := parseArgs[AnalyzeCVEArgs](request)
	if err != nil {
		logger.Warn().Err(err).Msg("invalid arguments")
		return errorResult(fmt.Errorf("invalid arguments: %w", err)), nil
	}

	// Validate vulnerability ID format (accepts CVE, GHSA, PYSEC, GO)
	if err := validateVulnID(args.CVEID); err != nil {
		return errorResult(err), nil
	}

	// Resolve non-CVE IDs (GHSA, PYSEC, etc.) to CVE using OSV
	cveID := args.CVEID
	if !isCVEID(args.CVEID) {
		resolved, err := ecosystem.DefaultOSVClient.ResolveCVEID(ctx, args.CVEID)
		if err != nil {
			return errorResult(fmt.Errorf("failed to resolve %s to CVE: %w", args.CVEID, err)), nil
		}
		if !isCVEID(resolved) {
			return errorResult(fmt.Errorf("%s has no CVE alias - Intel API requires CVE IDs", args.CVEID)), nil
		}
		cveID = resolved
	}

	req := &intel.AnalyzeCVERequest{
		CVEID: cveID,
	}
	if args.PackageName != "" {
		req.PackageName = &args.PackageName
	}
	if args.CurrentVersion != "" {
		req.CurrentVersion = &args.CurrentVersion
	}
	if args.Ecosystem != "" {
		req.Ecosystem = &args.Ecosystem
	}

	resp, err := s.intelClient.AnalyzeCVE(ctx, req)
	if err != nil {
		return errorResult(fmt.Errorf("analyze failed: %w", err)), nil
	}

	return jsonResult(resp)
}

func (s *Server) handleGetCVEVerdict(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	if s.intelClient == nil {
		return errorResult(fmt.Errorf("intel-engine not configured")), nil
	}

	args, err := parseArgs[GetCVEVerdictArgs](request)
	if err != nil {
		return errorResult(fmt.Errorf("invalid arguments: %w", err)), nil
	}

	// Validate vulnerability ID format
	if err := validateVulnID(args.CVEID); err != nil {
		return errorResult(err), nil
	}

	// Resolve non-CVE IDs to CVE using OSV
	cveID := args.CVEID
	if !isCVEID(args.CVEID) {
		resolved, err := ecosystem.DefaultOSVClient.ResolveCVEID(ctx, args.CVEID)
		if err != nil {
			return errorResult(fmt.Errorf("failed to resolve %s to CVE: %w", args.CVEID, err)), nil
		}
		if !isCVEID(resolved) {
			return errorResult(fmt.Errorf("%s has no CVE alias - Intel API requires CVE IDs", args.CVEID)), nil
		}
		cveID = resolved
	}

	resp, err := s.intelClient.GetCVEVerdict(ctx, cveID)
	if err != nil {
		return errorResult(fmt.Errorf("verdict lookup failed: %w", err)), nil
	}

	return jsonResult(resp)
}

func (s *Server) handleBatchTriage(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	if s.intelClient == nil {
		return errorResult(fmt.Errorf("intel-engine not configured")), nil
	}

	args, err := parseArgs[BatchTriageArgs](request)
	if err != nil {
		return errorResult(fmt.Errorf("invalid arguments: %w", err)), nil
	}

	// Validate batch size
	if len(args.CVEIDs) == 0 {
		return errorResult(fmt.Errorf("cve_ids cannot be empty")), nil
	}
	if len(args.CVEIDs) > 20 {
		return errorResult(fmt.Errorf("maximum 20 CVEs per batch, got %d", len(args.CVEIDs))), nil
	}

	// Validate and resolve each vulnerability ID to CVE (with deduplication)
	cveIDs := make([]string, 0, len(args.CVEIDs))
	seen := make(map[string]bool)         // Track seen input IDs
	resolved := make(map[string]string)   // Cache: input ID -> resolved CVE ID

	for _, id := range args.CVEIDs {
		// Skip duplicates
		if seen[id] {
			continue
		}
		seen[id] = true

		if err := validateVulnID(id); err != nil {
			return errorResult(err), nil
		}

		var cveID string
		if isCVEID(id) {
			cveID = id
		} else {
			// Check cache first
			if cached, ok := resolved[id]; ok {
				cveID = cached
			} else {
				resolvedID, err := ecosystem.DefaultOSVClient.ResolveCVEID(ctx, id)
				if err != nil {
					return errorResult(fmt.Errorf("failed to resolve %s to CVE: %w", id, err)), nil
				}
				if !isCVEID(resolvedID) {
					return errorResult(fmt.Errorf("%s has no CVE alias - Intel API requires CVE IDs", id)), nil
				}
				resolved[id] = resolvedID
				cveID = resolvedID
			}
		}

		// Dedupe resolved CVE IDs too (different GHSAs might resolve to same CVE)
		if !seen[cveID] {
			seen[cveID] = true
			cveIDs = append(cveIDs, cveID)
		}
	}

	resp, err := s.intelClient.BatchTriage(ctx, cveIDs)
	if err != nil {
		return errorResult(fmt.Errorf("batch triage failed: %w", err)), nil
	}

	return jsonResult(resp)
}

func (s *Server) handleCheckIfAffected(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args, err := parseArgs[CheckIfAffectedArgs](request)
	if err != nil {
		return errorResult(fmt.Errorf("invalid arguments: %w", err)), nil
	}

	// Validate vulnerability ID format (accepts CVE, GHSA, PYSEC, GO since this uses OSV directly)
	if err := validateVulnID(args.CVEID); err != nil {
		return errorResult(err), nil
	}

	// Validate required fields
	if strings.TrimSpace(args.PackageName) == "" {
		return errorResult(fmt.Errorf("package_name is required")), nil
	}
	if strings.TrimSpace(args.CurrentVersion) == "" {
		return errorResult(fmt.Errorf("current_version is required")), nil
	}
	if strings.TrimSpace(args.Ecosystem) == "" {
		return errorResult(fmt.Errorf("ecosystem is required")), nil
	}

	// Use local OSV + version comparison (no Intel-engine needed)
	pkg := ecosystem.Package{
		Name:      args.PackageName,
		Version:   args.CurrentVersion,
		Ecosystem: args.Ecosystem,
	}

	result, err := ecosystem.DefaultOSVClient.CheckIfAffected(ctx, args.CVEID, pkg)
	if err != nil {
		return errorResult(fmt.Errorf("check failed: %w", err)), nil
	}

	// Convert to response format
	response := CheckIfAffectedResponse{
		Status:     result.Status.String(),
		Message:    result.Message,
		FixVersion: result.FixVersion,
		Action:     determineAction(result.Status),
	}

	return jsonResult(response)
}

// CheckIfAffectedResponse is the response for check_if_affected tool.
type CheckIfAffectedResponse struct {
	Status     string `json:"status"`
	Message    string `json:"message"`
	FixVersion string `json:"fix_version,omitempty"`
	Action     string `json:"action"`
}

// determineAction returns the recommended action based on vulnerability status.
func determineAction(status version.VulnerabilityStatus) string {
	switch status {
	case version.StatusNotAffected:
		return "none_required"
	case version.StatusFixed:
		return "none_required"
	case version.StatusVulnerable:
		return "upgrade_recommended"
	default:
		return "investigate"
	}
}

type ScanProjectArgs struct {
	Path        string `json:"path"`
	Ecosystem   string `json:"ecosystem,omitempty"`
	NativeAudit bool   `json:"native_audit,omitempty"`
}

type ScanResponse struct {
	Path          string                   `json:"path"`
	Results       []*ecosystem.ScanResult  `json:"results"`
	TotalPackages int                      `json:"total_packages"`
	TotalVulns    int                      `json:"total_vulns"`
	Warnings      []string                 `json:"warnings,omitempty"`
}

type GetFixArgs struct {
	Ecosystem      string `json:"ecosystem"`
	PackageName    string `json:"package_name"`
	CurrentVersion string `json:"current_version"`
	FixVersion     string `json:"fix_version"`
}

func (s *Server) handleReportOutcome(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	if s.intelClient == nil {
		return errorResult(fmt.Errorf("intel-engine not configured")), nil
	}

	args, err := parseArgs[ReportOutcomeArgs](request)
	if err != nil {
		return errorResult(fmt.Errorf("invalid arguments: %w", err)), nil
	}

	// Validate vulnerability ID format
	if err := validateVulnID(args.CVEID); err != nil {
		return errorResult(err), nil
	}

	// Resolve non-CVE IDs to CVE using OSV
	cveID := args.CVEID
	if !isCVEID(args.CVEID) {
		resolved, err := ecosystem.DefaultOSVClient.ResolveCVEID(ctx, args.CVEID)
		if err != nil {
			return errorResult(fmt.Errorf("failed to resolve %s to CVE: %w", args.CVEID, err)), nil
		}
		if !isCVEID(resolved) {
			return errorResult(fmt.Errorf("%s has no CVE alias - Intel API requires CVE IDs", args.CVEID)), nil
		}
		cveID = resolved
	}

	// Validate required fields (trim whitespace to reject " " as valid)
	if strings.TrimSpace(args.PackageName) == "" {
		return errorResult(fmt.Errorf("package_name is required")), nil
	}
	if strings.TrimSpace(args.Ecosystem) == "" {
		return errorResult(fmt.Errorf("ecosystem is required")), nil
	}
	if strings.TrimSpace(args.FromVersion) == "" {
		return errorResult(fmt.Errorf("from_version is required")), nil
	}
	if strings.TrimSpace(args.ToVersion) == "" {
		return errorResult(fmt.Errorf("to_version is required")), nil
	}

	// Validate outcome
	validOutcomes := map[string]bool{"success": true, "failure": true, "partial": true}
	if !validOutcomes[args.Outcome] {
		return errorResult(fmt.Errorf("outcome must be one of: success, failure, partial")), nil
	}

	// Require failure_reason if outcome is not success
	if args.Outcome != "success" && args.FailureReason == "" {
		return errorResult(fmt.Errorf("failure_reason is required when outcome is not success")), nil
	}

	// Validate failure_reason if provided
	if args.FailureReason != "" {
		validReasons := map[string]bool{
			"command_failed":     true,
			"breaking_change":    true,
			"dependency_conflict": true,
			"cve_still_detected": true,
			"wrong_fix_version":  true,
			"not_affected":       true,
			"other":              true,
		}
		if !validReasons[args.FailureReason] {
			return errorResult(fmt.Errorf("invalid failure_reason: %s", args.FailureReason)), nil
		}
	}

	// Build request
	req := &intel.ReportOutcomeRequest{
		CVEID:       cveID,
		PackageName: args.PackageName,
		Ecosystem:   args.Ecosystem,
		FromVersion: args.FromVersion,
		ToVersion:   args.ToVersion,
		Outcome:     args.Outcome,
		Environment: args.Environment,
	}

	if args.FailureReason != "" {
		req.FailureReason = &args.FailureReason
	}
	if args.ErrorMessage != "" {
		req.ErrorMessage = &args.ErrorMessage
	}
	if args.BreakingChangeDetails != "" {
		req.BreakingChangeDetails = &args.BreakingChangeDetails
	}
	if args.AlternativeVersion != "" {
		req.AlternativeVersion = &args.AlternativeVersion
	}

	resp, err := s.intelClient.ReportOutcome(ctx, req)
	if err != nil {
		return errorResult(fmt.Errorf("failed to report outcome: %w", err)), nil
	}

	return jsonResult(resp)
}
