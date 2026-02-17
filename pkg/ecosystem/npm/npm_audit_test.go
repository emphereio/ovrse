package npm

import (
	"strings"
	"testing"

	"github.com/emphereio/ovrse/pkg/ecosystem"
)

// TestParseNpmAuditOutputEmptyVia tests that parseNpmAuditOutput handles empty Via arrays.
func TestParseNpmAuditOutputEmptyVia(t *testing.T) {
	// JSON with empty Via array - should not panic
	jsonData := []byte(`{
		"vulnerabilities": {
			"vulnerable-pkg": {
				"name": "vulnerable-pkg",
				"severity": "high",
				"range": ">=1.0.0 <2.0.0",
				"via": [],
				"fixAvailable": {
					"name": "vulnerable-pkg",
					"version": "2.0.0"
				}
			}
		},
		"metadata": {
			"totalDependencies": 100
		}
	}`)

	result, err := parseNpmAuditOutput(jsonData)
	if err != nil {
		t.Fatalf("parseNpmAuditOutput failed: %v", err)
	}

	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result.Findings))
	}

	finding := result.Findings[0]
	if len(finding.Vulnerabilities) != 1 {
		t.Fatalf("expected 1 vulnerability, got %d", len(finding.Vulnerabilities))
	}

	vuln := finding.Vulnerabilities[0]
	// Should have fallback ID when Via is empty
	if !strings.HasPrefix(vuln.ID, "npm-") {
		t.Errorf("expected fallback ID starting with 'npm-', got: %s", vuln.ID)
	}
	// Should have fallback summary
	if !strings.Contains(vuln.Summary, "Vulnerability in") {
		t.Errorf("expected fallback summary, got: %s", vuln.Summary)
	}
}

// TestParseNpmAuditOutputWithVia tests normal parsing with Via populated.
func TestParseNpmAuditOutputWithVia(t *testing.T) {
	jsonData := []byte(`{
		"vulnerabilities": {
			"lodash": {
				"name": "lodash",
				"severity": "high",
				"range": ">=4.0.0 <4.17.21",
				"via": [
					{
						"source": "1234",
						"title": "Prototype Pollution"
					}
				],
				"fixAvailable": {
					"name": "lodash",
					"version": "4.17.21"
				}
			}
		},
		"metadata": {
			"totalDependencies": 50
		}
	}`)

	result, err := parseNpmAuditOutput(jsonData)
	if err != nil {
		t.Fatalf("parseNpmAuditOutput failed: %v", err)
	}

	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result.Findings))
	}

	finding := result.Findings[0]
	vuln := finding.Vulnerabilities[0]

	if vuln.ID != "1234" {
		t.Errorf("expected ID '1234', got: %s", vuln.ID)
	}
	if vuln.Summary != "Prototype Pollution" {
		t.Errorf("expected summary 'Prototype Pollution', got: %s", vuln.Summary)
	}
	if vuln.FixVersion != "4.17.21" {
		t.Errorf("expected fix version '4.17.21', got: %s", vuln.FixVersion)
	}
	if vuln.Severity != "HIGH" {
		t.Errorf("expected severity 'HIGH', got: %s", vuln.Severity)
	}
}

// TestParseNpmAuditOutputMultipleVulns tests parsing multiple vulnerabilities.
func TestParseNpmAuditOutputMultipleVulns(t *testing.T) {
	jsonData := []byte(`{
		"vulnerabilities": {
			"pkg1": {
				"name": "pkg1",
				"severity": "critical",
				"range": "*",
				"via": [{"source": "CVE-1", "title": "Critical Bug"}],
				"fixAvailable": {"name": "pkg1", "version": "2.0.0"}
			},
			"pkg2": {
				"name": "pkg2",
				"severity": "low",
				"range": "*",
				"via": [{"source": "CVE-2", "title": "Minor Issue"}],
				"fixAvailable": {"name": "pkg2", "version": "1.1.0"}
			}
		},
		"metadata": {"totalDependencies": 200}
	}`)

	result, err := parseNpmAuditOutput(jsonData)
	if err != nil {
		t.Fatalf("parseNpmAuditOutput failed: %v", err)
	}

	if len(result.Findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(result.Findings))
	}
	if result.PackagesScanned != 200 {
		t.Errorf("expected 200 packages scanned, got %d", result.PackagesScanned)
	}
	if result.Status != ecosystem.ScanStatusSuccess {
		t.Errorf("expected success status, got %s", result.Status)
	}
}

// TestParseNpmAuditOutputInvalidJSON tests error handling for invalid JSON.
func TestParseNpmAuditOutputInvalidJSON(t *testing.T) {
	jsonData := []byte(`{invalid json}`)

	_, err := parseNpmAuditOutput(jsonData)
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

// TestParseNpmAuditOutputEmpty tests parsing empty vulnerabilities.
func TestParseNpmAuditOutputEmpty(t *testing.T) {
	jsonData := []byte(`{
		"vulnerabilities": {},
		"metadata": {"totalDependencies": 50}
	}`)

	result, err := parseNpmAuditOutput(jsonData)
	if err != nil {
		t.Fatalf("parseNpmAuditOutput failed: %v", err)
	}

	if len(result.Findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(result.Findings))
	}
	if result.Status != ecosystem.ScanStatusSuccess {
		t.Errorf("expected success status, got %s", result.Status)
	}
}
