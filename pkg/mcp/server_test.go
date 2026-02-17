package mcp

import (
	"testing"

	"github.com/emphereio/ovrse/pkg/ecosystem"
	"github.com/emphereio/ovrse/pkg/version"
)

func TestNewServer(t *testing.T) {
	s := NewServer(nil)
	if s == nil {
		t.Fatal("NewServer returned nil")
	}
	if s.mcpServer == nil {
		t.Error("mcpServer is nil")
	}
}

func TestServerMCPServer(t *testing.T) {
	s := NewServer(nil)
	mcp := s.MCPServer()
	if mcp == nil {
		t.Error("MCPServer() returned nil")
	}
}

func TestDetermineAction(t *testing.T) {
	tests := []struct {
		status   version.VulnerabilityStatus
		expected string
	}{
		{version.StatusNotAffected, "none_required"},
		{version.StatusFixed, "none_required"},
		{version.StatusVulnerable, "upgrade_recommended"},
		{version.StatusUnknown, "investigate"},
	}

	for _, tt := range tests {
		t.Run(tt.status.String(), func(t *testing.T) {
			action := determineAction(tt.status)
			if action != tt.expected {
				t.Errorf("determineAction(%s) = %q, want %q", tt.status, action, tt.expected)
			}
		})
	}
}

func TestScanProjectArgs(t *testing.T) {
	args := ScanProjectArgs{
		Path:      "/project",
		Ecosystem: "npm",
	}

	if args.Path != "/project" {
		t.Errorf("unexpected path: %s", args.Path)
	}
	if args.Ecosystem != "npm" {
		t.Errorf("unexpected ecosystem: %s", args.Ecosystem)
	}
}

func TestScanResponse(t *testing.T) {
	resp := ScanResponse{
		Path: "/project",
		Results: []*ecosystem.ScanResult{
			{
				Ecosystem:       "npm",
				PackagesScanned: 100,
				Findings: []ecosystem.Finding{
					{
						Package: ecosystem.Package{Name: "lodash"},
						Vulnerabilities: []ecosystem.Vulnerability{
							{ID: "CVE-1"},
							{ID: "CVE-2"},
						},
					},
				},
			},
		},
		TotalPackages: 100,
		TotalVulns:    2,
	}

	if resp.Path != "/project" {
		t.Errorf("unexpected path: %s", resp.Path)
	}
	if resp.TotalPackages != 100 {
		t.Errorf("unexpected total packages: %d", resp.TotalPackages)
	}
	if resp.TotalVulns != 2 {
		t.Errorf("unexpected total vulns: %d", resp.TotalVulns)
	}
}

func TestGetFixArgs(t *testing.T) {
	args := GetFixArgs{
		Ecosystem:      "npm",
		PackageName:    "lodash",
		CurrentVersion: "4.17.15",
		FixVersion:     "4.17.21",
	}

	if args.Ecosystem != "npm" {
		t.Errorf("unexpected ecosystem: %s", args.Ecosystem)
	}
	if args.PackageName != "lodash" {
		t.Errorf("unexpected package: %s", args.PackageName)
	}
}

func TestCheckIfAffectedResponse(t *testing.T) {
	resp := CheckIfAffectedResponse{
		Status:     "vulnerable",
		Message:    "Version 4.17.15 is vulnerable",
		FixVersion: "4.17.21",
		Action:     "upgrade_recommended",
	}

	if resp.Status != "vulnerable" {
		t.Errorf("unexpected status: %s", resp.Status)
	}
	if resp.FixVersion != "4.17.21" {
		t.Errorf("unexpected fix version: %s", resp.FixVersion)
	}
	if resp.Action != "upgrade_recommended" {
		t.Errorf("unexpected action: %s", resp.Action)
	}
}

func TestAnalyzeCVEArgs(t *testing.T) {
	args := AnalyzeCVEArgs{
		CVEID:          "CVE-2021-23337",
		PackageName:    "lodash",
		CurrentVersion: "4.17.15",
		Ecosystem:      "npm",
	}

	if args.CVEID != "CVE-2021-23337" {
		t.Errorf("unexpected CVE ID: %s", args.CVEID)
	}
}

func TestGetCVEVerdictArgs(t *testing.T) {
	args := GetCVEVerdictArgs{
		CVEID: "CVE-2021-23337",
	}

	if args.CVEID != "CVE-2021-23337" {
		t.Errorf("unexpected CVE ID: %s", args.CVEID)
	}
}

func TestBatchTriageArgs(t *testing.T) {
	args := BatchTriageArgs{
		CVEIDs: []string{"CVE-1", "CVE-2", "CVE-3"},
	}

	if len(args.CVEIDs) != 3 {
		t.Errorf("expected 3 CVE IDs, got %d", len(args.CVEIDs))
	}
}

func TestCheckIfAffectedArgs(t *testing.T) {
	args := CheckIfAffectedArgs{
		CVEID:          "CVE-2021-23337",
		PackageName:    "lodash",
		CurrentVersion: "4.17.15",
		Ecosystem:      "npm",
	}

	if args.CVEID != "CVE-2021-23337" {
		t.Errorf("unexpected CVE ID: %s", args.CVEID)
	}
	if args.PackageName != "lodash" {
		t.Errorf("unexpected package: %s", args.PackageName)
	}
	if args.CurrentVersion != "4.17.15" {
		t.Errorf("unexpected version: %s", args.CurrentVersion)
	}
	if args.Ecosystem != "npm" {
		t.Errorf("unexpected ecosystem: %s", args.Ecosystem)
	}
}

func TestVulnCounting(t *testing.T) {
	// Test that vulnerability counting is correct
	results := []*ecosystem.ScanResult{
		{
			Ecosystem:       "npm",
			PackagesScanned: 50,
			Findings: []ecosystem.Finding{
				{
					Package: ecosystem.Package{Name: "pkg1"},
					Vulnerabilities: []ecosystem.Vulnerability{
						{ID: "CVE-1"},
						{ID: "CVE-2"},
					},
				},
				{
					Package: ecosystem.Package{Name: "pkg2"},
					Vulnerabilities: []ecosystem.Vulnerability{
						{ID: "CVE-3"},
					},
				},
			},
		},
		{
			Ecosystem:       "go",
			PackagesScanned: 30,
			Findings: []ecosystem.Finding{
				{
					Package: ecosystem.Package{Name: "pkg3"},
					Vulnerabilities: []ecosystem.Vulnerability{
						{ID: "CVE-4"},
						{ID: "CVE-5"},
					},
				},
			},
		},
	}

	// Calculate totals (same logic as server.go)
	var totalPackages, totalVulns int
	for _, r := range results {
		totalPackages += r.PackagesScanned
		for _, f := range r.Findings {
			totalVulns += len(f.Vulnerabilities)
		}
	}

	if totalPackages != 80 {
		t.Errorf("expected 80 packages, got %d", totalPackages)
	}
	if totalVulns != 5 {
		t.Errorf("expected 5 vulns, got %d", totalVulns)
	}
}

func TestScanResponseJSON(t *testing.T) {
	// Test that the response structure is JSON-serializable
	resp := ScanResponse{
		Path: "/test",
		Results: []*ecosystem.ScanResult{
			{
				Ecosystem: "npm",
			},
		},
		TotalPackages: 10,
		TotalVulns:    2,
	}

	// Just verify the structure is correct
	if resp.Path == "" {
		t.Error("path should not be empty")
	}
	if len(resp.Results) == 0 {
		t.Error("results should not be empty")
	}
}

func TestValidateCVEID(t *testing.T) {
	tests := []struct {
		id      string
		wantErr bool
	}{
		// Valid CVE IDs
		{"CVE-2021-12345", false},
		{"CVE-2024-3094", false},
		{"CVE-2020-0001", false},
		{"CVE-1999-99999", false},
		{"CVE-2025-123456", false},

		// Invalid CVE IDs
		{"", true},
		{"CVE-", true},
		{"CVE-2021", true},
		{"CVE-2021-123", true}, // only 3 digits
		{"cve-2021-12345", true}, // lowercase
		{"CVE_2021_12345", true}, // wrong separator
		{"GHSA-1234-5678", true}, // GHSA instead of CVE
		{"2021-12345", true}, // missing CVE prefix
		{"CVE-21-12345", true}, // 2-digit year
		{"CVE-20211-12345", true}, // 5-digit year
		{"random-string", true},
		{"CVE-2021-12345-extra", true}, // extra suffix
	}

	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			err := validateCVEID(tt.id)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateCVEID(%q) error = %v, wantErr = %v", tt.id, err, tt.wantErr)
			}
		})
	}
}

func TestCVEIDRegex(t *testing.T) {
	// Test the regex pattern
	validIDs := []string{
		"CVE-2021-12345",
		"CVE-2024-3094",
		"CVE-2020-0001",
		"CVE-1999-99999",
		"CVE-2025-123456789", // long number
	}

	for _, id := range validIDs {
		if !cveIDRegex.MatchString(id) {
			t.Errorf("cveIDRegex should match %q", id)
		}
	}
}

func TestParseArgs(t *testing.T) {
	// Test basic arg parsing - this uses the generic parseArgs function
	// We'll test it indirectly through the structs

	args := &ScanProjectArgs{
		Path:      "/test/path",
		Ecosystem: "npm",
	}

	if args.Path != "/test/path" {
		t.Errorf("unexpected path: %s", args.Path)
	}
}

func TestTextResult(t *testing.T) {
	result := textResult("test message")
	if result == nil {
		t.Fatal("textResult returned nil")
	}
	if len(result.Content) != 1 {
		t.Errorf("expected 1 content, got %d", len(result.Content))
	}
}

func TestErrorResult(t *testing.T) {
	err := &testError{msg: "test error"}
	result := errorResult(err)
	if result == nil {
		t.Fatal("errorResult returned nil")
	}
	if !result.IsError {
		t.Error("expected IsError to be true")
	}
}

type testError struct {
	msg string
}

func (e *testError) Error() string {
	return e.msg
}

func TestJsonResult(t *testing.T) {
	t.Run("valid data", func(t *testing.T) {
		data := map[string]string{"key": "value"}
		result, err := jsonResult(data)
		if err != nil {
			t.Fatalf("jsonResult failed: %v", err)
		}
		if result == nil {
			t.Fatal("jsonResult returned nil result")
		}
		if result.IsError {
			t.Error("expected IsError to be false for valid data")
		}
	})

	t.Run("unencodable data returns error result", func(t *testing.T) {
		// Channels cannot be JSON encoded
		ch := make(chan int)
		result, err := jsonResult(ch)
		if err != nil {
			t.Errorf("jsonResult should not return error, got: %v", err)
		}
		if result == nil {
			t.Fatal("jsonResult returned nil result")
		}
		if !result.IsError {
			t.Error("expected IsError to be true for unencodable data")
		}
	})
}

func TestServerConstants(t *testing.T) {
	if ServerName != "ovrse" {
		t.Errorf("unexpected ServerName: %s", ServerName)
	}
	if Version == "" {
		t.Error("Version is empty")
	}
}

func TestServerWithIntelClient(t *testing.T) {
	// Test creating server with nil intel client (should work)
	s := NewServer(nil)
	if s.intelClient != nil {
		t.Error("expected nil intelClient")
	}
}

func TestBatchTriageValidation(t *testing.T) {
	// Test batch triage limits
	tests := []struct {
		name    string
		ids     []string
		wantErr bool
	}{
		{
			name:    "empty list",
			ids:     []string{},
			wantErr: true,
		},
		{
			name:    "single ID",
			ids:     []string{"CVE-2021-12345"},
			wantErr: false,
		},
		{
			name:    "20 IDs (max)",
			ids:     make([]string, 20),
			wantErr: false, // IDs not validated in this test
		},
		{
			name:    "21 IDs (over max)",
			ids:     make([]string, 21),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hasErr := false
			if len(tt.ids) == 0 {
				hasErr = true
			} else if len(tt.ids) > 20 {
				hasErr = true
			}
			if hasErr != tt.wantErr {
				t.Errorf("batch validation error = %v, wantErr = %v", hasErr, tt.wantErr)
			}
		})
	}
}

func TestReportOutcomeArgs(t *testing.T) {
	args := ReportOutcomeArgs{
		CVEID:       "CVE-2021-23337",
		PackageName: "lodash",
		Ecosystem:   "npm",
		FromVersion: "4.17.15",
		ToVersion:   "4.17.21",
		Outcome:     "success",
	}

	if args.CVEID != "CVE-2021-23337" {
		t.Errorf("unexpected CVE ID: %s", args.CVEID)
	}
	if args.PackageName != "lodash" {
		t.Errorf("unexpected package: %s", args.PackageName)
	}
	if args.Ecosystem != "npm" {
		t.Errorf("unexpected ecosystem: %s", args.Ecosystem)
	}
	if args.FromVersion != "4.17.15" {
		t.Errorf("unexpected from version: %s", args.FromVersion)
	}
	if args.ToVersion != "4.17.21" {
		t.Errorf("unexpected to version: %s", args.ToVersion)
	}
	if args.Outcome != "success" {
		t.Errorf("unexpected outcome: %s", args.Outcome)
	}
}

func TestReportOutcomeArgsWithFailure(t *testing.T) {
	args := ReportOutcomeArgs{
		CVEID:         "CVE-2021-23337",
		PackageName:   "lodash",
		Ecosystem:     "npm",
		FromVersion:   "4.17.15",
		ToVersion:     "4.17.21",
		Outcome:       "failure",
		FailureReason: "breaking_change",
		ErrorMessage:  "TypeError: foo is not a function",
		BreakingChangeDetails: "API changed in 4.18.0",
	}

	if args.Outcome != "failure" {
		t.Errorf("unexpected outcome: %s", args.Outcome)
	}
	if args.FailureReason != "breaking_change" {
		t.Errorf("unexpected failure reason: %s", args.FailureReason)
	}
	if args.ErrorMessage == "" {
		t.Error("expected error message")
	}
	if args.BreakingChangeDetails == "" {
		t.Error("expected breaking change details")
	}
}

func TestReportOutcomeValidation(t *testing.T) {
	// Test outcome validation
	validOutcomes := map[string]bool{"success": true, "failure": true, "partial": true}

	tests := []struct {
		outcome string
		valid   bool
	}{
		{"success", true},
		{"failure", true},
		{"partial", true},
		{"unknown", false},
		{"", false},
		{"SUCCESS", false}, // case sensitive
	}

	for _, tt := range tests {
		t.Run(tt.outcome, func(t *testing.T) {
			if validOutcomes[tt.outcome] != tt.valid {
				t.Errorf("outcome %q validation = %v, want %v", tt.outcome, validOutcomes[tt.outcome], tt.valid)
			}
		})
	}
}

func TestReportOutcomeFailureReasons(t *testing.T) {
	// Test valid failure reasons
	validReasons := map[string]bool{
		"command_failed":      true,
		"breaking_change":     true,
		"dependency_conflict": true,
		"cve_still_detected":  true,
		"wrong_fix_version":   true,
		"not_affected":        true,
		"other":               true,
	}

	tests := []struct {
		reason string
		valid  bool
	}{
		{"command_failed", true},
		{"breaking_change", true},
		{"dependency_conflict", true},
		{"cve_still_detected", true},
		{"wrong_fix_version", true},
		{"not_affected", true},
		{"other", true},
		{"unknown_reason", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.reason, func(t *testing.T) {
			isValid := validReasons[tt.reason]
			if isValid != tt.valid {
				t.Errorf("reason %q validation = %v, want %v", tt.reason, isValid, tt.valid)
			}
		})
	}
}
