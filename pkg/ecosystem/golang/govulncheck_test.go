package golang

import (
	"context"
	"os/exec"
	"testing"
)

const sampleGovulncheckOutput = `{"config":{"protocol_version":"v1.0.0","scanner_name":"govulncheck","scanner_version":"v1.0.0","db":"https://vuln.go.dev","go_version":"go1.21.0"}}
{"progress":{"message":"Scanning your code and 42 packages across 10 dependent modules for known vulnerabilities..."}}
{"osv":{"id":"GO-2023-1621","aliases":["CVE-2023-24534"],"summary":"Excessive memory allocation in net/http","details":"HTTP and MIME header parsing can allocate large amounts of memory.","affected":[{"package":{"ecosystem":"Go","name":"stdlib"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"1.19.8"}]}],"database_specific":{"severity":"HIGH"}}]}}
{"osv":{"id":"GO-2023-1840","aliases":["CVE-2023-29400"],"summary":"Templates do not properly consider backticks","details":"Templates containing actions in unquoted HTML attributes executed with empty input could result in output that would be treated as an attribute name.","affected":[{"package":{"ecosystem":"Go","name":"github.com/example/vuln"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"v1.2.3"}]}]}]}}
{"finding":{"osv":"GO-2023-1621","trace":[{"module":"stdlib","version":"v1.19.0","package":"net/http","function":"ListenAndServe"}]}}
{"finding":{"osv":"GO-2023-1840","trace":[{"module":"github.com/example/vuln","version":"v1.0.0"}]}}
`

func TestParseGovulncheckOutput(t *testing.T) {
	result, err := parseGovulncheckOutput([]byte(sampleGovulncheckOutput))
	if err != nil {
		t.Fatalf("parseGovulncheckOutput failed: %v", err)
	}

	if len(result.OSVs) != 2 {
		t.Errorf("expected 2 OSV entries, got %d", len(result.OSVs))
	}

	if len(result.Findings) != 2 {
		t.Errorf("expected 2 findings, got %d", len(result.Findings))
	}

	osv1, ok := result.OSVs["GO-2023-1621"]
	if !ok {
		t.Fatal("expected OSV GO-2023-1621")
	}
	if osv1.Summary != "Excessive memory allocation in net/http" {
		t.Errorf("unexpected summary: %s", osv1.Summary)
	}
	if len(osv1.Aliases) != 1 || osv1.Aliases[0] != "CVE-2023-24534" {
		t.Errorf("unexpected aliases: %v", osv1.Aliases)
	}

	findings := result.toEcosystemFindings()
	if len(findings) != 2 {
		t.Fatalf("expected 2 ecosystem findings, got %d", len(findings))
	}

	for _, f := range findings {
		if len(f.Vulnerabilities) == 0 {
			t.Errorf("finding for %s has no vulnerabilities", f.Package.Name)
		}
		for _, v := range f.Vulnerabilities {
			if v.ID == "" {
				t.Error("vulnerability has empty ID")
			}
			if v.Summary == "" {
				t.Error("vulnerability has empty summary")
			}
		}
	}
}

func TestParseGovulncheckNoVulns(t *testing.T) {
	output := `{"config":{"protocol_version":"v1.0.0","scanner_name":"govulncheck","scanner_version":"v1.0.0","db":"https://vuln.go.dev","go_version":"go1.21.0"}}
{"progress":{"message":"Scanning your code and 20 packages across 5 dependent modules for known vulnerabilities..."}}
`
	result, err := parseGovulncheckOutput([]byte(output))
	if err != nil {
		t.Fatalf("parseGovulncheckOutput failed: %v", err)
	}

	if len(result.OSVs) != 0 {
		t.Errorf("expected 0 OSV entries, got %d", len(result.OSVs))
	}
	if len(result.Findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(result.Findings))
	}

	findings := result.toEcosystemFindings()
	if len(findings) != 0 {
		t.Errorf("expected 0 ecosystem findings, got %d", len(findings))
	}
}

func TestGovulncheckNotInstalled(t *testing.T) {
	// Only run if govulncheck is NOT installed
	if _, err := exec.LookPath("govulncheck"); err == nil {
		t.Skip("govulncheck is installed, skipping not-installed test")
	}

	p := &Plugin{}
	_, err := p.NativeAudit(context.Background(), t.TempDir())
	if err == nil {
		t.Fatal("expected error when govulncheck is not installed")
	}
	if got := err.Error(); got != "govulncheck not installed (go install golang.org/x/vuln/cmd/govulncheck@latest)" {
		t.Errorf("unexpected error message: %s", got)
	}
}

func TestExtractFixVersion(t *testing.T) {
	t.Run("single range", func(t *testing.T) {
		osv := &govulncheckOSV{
			ID: "GO-2023-1840",
			Affected: []govulncheckAffected{
				makeAffected("github.com/example/vuln",
					govulncheckRange{Type: "SEMVER", Events: []govulncheckEvent{
						{Introduced: "0"}, {Fixed: "v1.2.3"},
					}},
				),
			},
		}

		fix := extractFixVersion(osv, "github.com/example/vuln", "v1.0.0")
		if fix != "v1.2.3" {
			t.Errorf("expected v1.2.3, got %s", fix)
		}
	})

	t.Run("multi-range picks correct fix", func(t *testing.T) {
		osv := &govulncheckOSV{
			ID: "GO-2024-MULTI",
			Affected: []govulncheckAffected{
				makeAffected("github.com/example/vuln",
					govulncheckRange{Type: "SEMVER", Events: []govulncheckEvent{
						{Introduced: "0"}, {Fixed: "v1.5.0"},
						{Introduced: "v2.0.0"}, {Fixed: "v2.3.0"},
					}},
				),
			},
		}

		// v1.0.0 is in the first range [0, v1.5.0)
		if fix := extractFixVersion(osv, "github.com/example/vuln", "v1.0.0"); fix != "v1.5.0" {
			t.Errorf("v1.0.0: expected v1.5.0, got %s", fix)
		}

		// v2.1.0 is in the second range [v2.0.0, v2.3.0)
		if fix := extractFixVersion(osv, "github.com/example/vuln", "v2.1.0"); fix != "v2.3.0" {
			t.Errorf("v2.1.0: expected v2.3.0, got %s", fix)
		}
	})

	t.Run("multi-range across separate ranges", func(t *testing.T) {
		osv := &govulncheckOSV{
			ID: "GO-2024-SEPARATE",
			Affected: []govulncheckAffected{
				makeAffected("github.com/example/vuln",
					govulncheckRange{Type: "SEMVER", Events: []govulncheckEvent{
						{Introduced: "0"}, {Fixed: "v1.5.0"},
					}},
					govulncheckRange{Type: "SEMVER", Events: []govulncheckEvent{
						{Introduced: "v2.0.0"}, {Fixed: "v2.3.0"},
					}},
				),
			},
		}

		if fix := extractFixVersion(osv, "github.com/example/vuln", "v2.1.0"); fix != "v2.3.0" {
			t.Errorf("v2.1.0: expected v2.3.0, got %s", fix)
		}
	})

	t.Run("stdlib without v prefix", func(t *testing.T) {
		osv := &govulncheckOSV{
			ID: "GO-2023-1621",
			Affected: []govulncheckAffected{
				makeAffected("stdlib",
					govulncheckRange{Type: "SEMVER", Events: []govulncheckEvent{
						{Introduced: "0"}, {Fixed: "1.19.8"},
						{Introduced: "1.20.0"}, {Fixed: "1.20.3"},
					}},
				),
			},
		}

		if fix := extractFixVersion(osv, "stdlib", "v1.19.0"); fix != "1.19.8" {
			t.Errorf("v1.19.0: expected 1.19.8, got %s", fix)
		}
		if fix := extractFixVersion(osv, "stdlib", "v1.20.1"); fix != "1.20.3" {
			t.Errorf("v1.20.1: expected 1.20.3, got %s", fix)
		}
	})

	t.Run("empty version falls back to first fix", func(t *testing.T) {
		osv := &govulncheckOSV{
			ID: "GO-2024-NOVERSION",
			Affected: []govulncheckAffected{
				makeAffected("github.com/example/vuln",
					govulncheckRange{Type: "SEMVER", Events: []govulncheckEvent{
						{Introduced: "0"}, {Fixed: "v1.5.0"},
						{Introduced: "v2.0.0"}, {Fixed: "v2.3.0"},
					}},
				),
			},
		}

		if fix := extractFixVersion(osv, "github.com/example/vuln", ""); fix != "v1.5.0" {
			t.Errorf("empty version: expected fallback v1.5.0, got %s", fix)
		}
	})

	t.Run("module fallback", func(t *testing.T) {
		osv := &govulncheckOSV{
			ID: "GO-2023-1840",
			Affected: []govulncheckAffected{
				makeAffected("github.com/example/vuln",
					govulncheckRange{Type: "SEMVER", Events: []govulncheckEvent{
						{Introduced: "0"}, {Fixed: "v1.2.3"},
					}},
				),
			},
		}

		fix := extractFixVersion(osv, "github.com/other/module", "v1.0.0")
		if fix != "v1.2.3" {
			t.Errorf("expected fallback v1.2.3, got %s", fix)
		}
	})
}

func makeAffected(name string, ranges ...govulncheckRange) govulncheckAffected {
	return govulncheckAffected{
		Package: struct {
			Ecosystem string `json:"ecosystem"`
			Name      string `json:"name"`
		}{
			Ecosystem: "Go",
			Name:      name,
		},
		Ranges: ranges,
	}
}

func TestParseModuleCount(t *testing.T) {
	tests := []struct {
		msg      string
		expected int
	}{
		{"Scanning your code and 42 packages across 10 dependent modules for known vulnerabilities...", 10},
		{"Scanning your code and 3 packages across 1 dependent modules for known vulnerabilities...", 1},
		{"Loading packages...", 0},
		{"", 0},
	}

	for _, tt := range tests {
		got := parseModuleCount(tt.msg)
		if got != tt.expected {
			t.Errorf("parseModuleCount(%q) = %d, want %d", tt.msg, got, tt.expected)
		}
	}
}

func TestScannedModulesFromProgress(t *testing.T) {
	result, err := parseGovulncheckOutput([]byte(sampleGovulncheckOutput))
	if err != nil {
		t.Fatalf("parseGovulncheckOutput failed: %v", err)
	}

	if result.ScannedModules != 10 {
		t.Errorf("expected ScannedModules=10, got %d", result.ScannedModules)
	}
}

func TestScannedModulesZeroOnCleanScan(t *testing.T) {
	output := `{"config":{"protocol_version":"v1.0.0"}}
{"progress":{"message":"Scanning your code and 20 packages across 5 dependent modules for known vulnerabilities..."}}
`
	result, err := parseGovulncheckOutput([]byte(output))
	if err != nil {
		t.Fatalf("parseGovulncheckOutput failed: %v", err)
	}

	if result.ScannedModules != 5 {
		t.Errorf("expected ScannedModules=5, got %d", result.ScannedModules)
	}

	findings := result.toEcosystemFindings()
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}

func TestScannedModulesFromSBOM(t *testing.T) {
	output := `{"config":{"protocol_version":"v1.0.0","scanner_version":"v1.1.4"}}
{"SBOM":{"go_version":"go1.25.5","modules":[{"path":"example.com/app"},{"path":"github.com/foo/bar","version":"v1.0.0"},{"path":"github.com/baz/qux","version":"v0.2.0"}]}}
{"progress":{"message":"Fetching vulnerabilities from the database..."}}
{"progress":{"message":"Checking the code against the vulnerabilities..."}}
`
	result, err := parseGovulncheckOutput([]byte(output))
	if err != nil {
		t.Fatalf("parseGovulncheckOutput failed: %v", err)
	}

	if result.ScannedModules != 3 {
		t.Errorf("expected ScannedModules=3 (from SBOM), got %d", result.ScannedModules)
	}
}

func TestExtractSeverity(t *testing.T) {
	t.Run("from database_specific", func(t *testing.T) {
		osv := &govulncheckOSV{
			DatabaseSpecific: &govulncheckDBSpecific{Severity: "high"},
		}
		if s := extractSeverity(osv); s != "HIGH" {
			t.Errorf("expected HIGH, got %s", s)
		}
	})

	t.Run("from affected entry", func(t *testing.T) {
		osv := &govulncheckOSV{
			Affected: []govulncheckAffected{
				{DatabaseSpecific: &govulncheckDBSpecific{Severity: "critical"}},
			},
		}
		if s := extractSeverity(osv); s != "CRITICAL" {
			t.Errorf("expected CRITICAL, got %s", s)
		}
	})

	t.Run("missing defaults to UNKNOWN", func(t *testing.T) {
		osv := &govulncheckOSV{}
		if s := extractSeverity(osv); s != "UNKNOWN" {
			t.Errorf("expected UNKNOWN, got %s", s)
		}
	})
}
