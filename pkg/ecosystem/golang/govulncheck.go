package golang

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/emphereio/ovrse/pkg/ecosystem"
)

// govulncheckMessage is a single JSON object from govulncheck's streaming output.
type govulncheckMessage struct {
	Config   *govulncheckConfig   `json:"config,omitempty"`
	Progress *govulncheckProgress `json:"progress,omitempty"`
	SBOM     *govulncheckSBOM     `json:"SBOM,omitempty"`
	OSV      *govulncheckOSV      `json:"osv,omitempty"`
	Finding  *govulncheckFinding  `json:"finding,omitempty"`
}

type govulncheckConfig struct {
	ProtocolVersion string `json:"protocol_version"`
	GoVersion       string `json:"go_version"`
}

type govulncheckProgress struct {
	Message string `json:"message"`
}

type govulncheckSBOM struct {
	Modules []struct {
		Path    string `json:"path"`
		Version string `json:"version,omitempty"`
	} `json:"modules"`
}

type govulncheckOSV struct {
	ID       string   `json:"id"`
	Aliases  []string `json:"aliases"`
	Summary  string   `json:"summary"`
	Details  string   `json:"details"`
	Affected []govulncheckAffected `json:"affected"`
	DatabaseSpecific *govulncheckDBSpecific `json:"database_specific,omitempty"`
}

type govulncheckAffected struct {
	Package struct {
		Ecosystem string `json:"ecosystem"`
		Name      string `json:"name"`
	} `json:"package"`
	Ranges []govulncheckRange `json:"ranges"`
	DatabaseSpecific *govulncheckDBSpecific `json:"database_specific,omitempty"`
}

type govulncheckRange struct {
	Type   string              `json:"type"`
	Events []govulncheckEvent  `json:"events"`
}

type govulncheckEvent struct {
	Introduced string `json:"introduced,omitempty"`
	Fixed      string `json:"fixed,omitempty"`
}

type govulncheckDBSpecific struct {
	Severity string `json:"severity,omitempty"`
}

type govulncheckFinding struct {
	OSV   string                  `json:"osv"`
	Trace []govulncheckTraceEntry `json:"trace"`
}

type govulncheckTraceEntry struct {
	Module   string `json:"module,omitempty"`
	Version  string `json:"version,omitempty"`
	Package  string `json:"package,omitempty"`
	Function string `json:"function,omitempty"`
}

type govulncheckResult struct {
	OSVs           map[string]*govulncheckOSV
	Findings       []*govulncheckFinding
	ScannedModules int
}

func parseGovulncheckOutput(data []byte) (*govulncheckResult, error) {
	result := &govulncheckResult{
		OSVs: make(map[string]*govulncheckOSV),
	}

	decoder := json.NewDecoder(bytes.NewReader(data))
	for decoder.More() {
		var msg govulncheckMessage
		if err := decoder.Decode(&msg); err != nil {
			return nil, fmt.Errorf("failed to decode govulncheck message: %w", err)
		}

		if msg.SBOM != nil {
			result.ScannedModules = len(msg.SBOM.Modules)
		}
		if msg.Progress != nil && result.ScannedModules == 0 {
			result.ScannedModules = parseModuleCount(msg.Progress.Message)
		}
		if msg.OSV != nil {
			result.OSVs[msg.OSV.ID] = msg.OSV
		}
		if msg.Finding != nil {
			result.Findings = append(result.Findings, msg.Finding)
		}
	}

	return result, nil
}

func (r *govulncheckResult) toEcosystemFindings() []ecosystem.Finding {
	type pkgKey struct {
		Module  string
		Version string
	}

	pkgFindings := make(map[pkgKey]map[string]ecosystem.Vulnerability)

	for _, f := range r.Findings {
		if len(f.Trace) == 0 {
			continue
		}

		entry := f.Trace[0]
		key := pkgKey{Module: entry.Module, Version: entry.Version}

		if pkgFindings[key] == nil {
			pkgFindings[key] = make(map[string]ecosystem.Vulnerability)
		}

		if _, exists := pkgFindings[key][f.OSV]; exists {
			continue
		}

		vuln := ecosystem.Vulnerability{
			ID: f.OSV,
		}

		if osv, ok := r.OSVs[f.OSV]; ok {
			vuln.Summary = osv.Summary
			vuln.Details = osv.Details
			vuln.Aliases = osv.Aliases
			vuln.Severity = extractSeverity(osv)
			vuln.FixVersion = extractFixVersion(osv, entry.Module)
		}

		pkgFindings[key][f.OSV] = vuln
	}

	var findings []ecosystem.Finding
	for key, vulns := range pkgFindings {
		var vulnList []ecosystem.Vulnerability
		for _, v := range vulns {
			vulnList = append(vulnList, v)
		}
		sort.Slice(vulnList, func(i, j int) bool {
			return vulnList[i].ID < vulnList[j].ID
		})

		findings = append(findings, ecosystem.Finding{
			Package: ecosystem.Package{
				Name:      key.Module,
				Version:   key.Version,
				Ecosystem: "Go",
			},
			Vulnerabilities: vulnList,
		})
	}

	sort.Slice(findings, func(i, j int) bool {
		if findings[i].Package.Name != findings[j].Package.Name {
			return findings[i].Package.Name < findings[j].Package.Name
		}
		return findings[i].Package.Version < findings[j].Package.Version
	})

	return findings
}

func extractSeverity(osv *govulncheckOSV) string {
	if osv.DatabaseSpecific != nil && osv.DatabaseSpecific.Severity != "" {
		return strings.ToUpper(osv.DatabaseSpecific.Severity)
	}
	for _, a := range osv.Affected {
		if a.DatabaseSpecific != nil && a.DatabaseSpecific.Severity != "" {
			return strings.ToUpper(a.DatabaseSpecific.Severity)
		}
	}
	return "UNKNOWN"
}

// extractFixVersion returns the fix version for a module from OSV affected ranges.
// BUG(#40): Returns the first "fixed" event, which is incorrect for multi-range
// entries. A module at v2.1 with ranges [{introduced:0,fixed:1.5},{introduced:2.0,
// fixed:2.3}] would incorrectly get 1.5 instead of 2.3.
func extractFixVersion(osv *govulncheckOSV, module string) string {
	for _, a := range osv.Affected {
		if a.Package.Name == module {
			for _, r := range a.Ranges {
				for _, e := range r.Events {
					if e.Fixed != "" {
						return e.Fixed
					}
				}
			}
		}
	}
	// Fallback: try any affected entry
	for _, a := range osv.Affected {
		for _, r := range a.Ranges {
			for _, e := range r.Events {
				if e.Fixed != "" {
					return e.Fixed
				}
			}
		}
	}
	return ""
}

var moduleCountRegex = regexp.MustCompile(`across (\d+) dependent modules`)

func parseModuleCount(msg string) int {
	if m := moduleCountRegex.FindStringSubmatch(msg); len(m) == 2 {
		n, _ := strconv.Atoi(m[1])
		return n
	}
	return 0
}

func runGovulncheck(ctx context.Context, path string) (*govulncheckResult, error) {
	cmd := exec.CommandContext(ctx, "govulncheck", "-json", "./...")
	cmd.Dir = path

	output, err := cmd.Output()
	if err != nil {
		// Non-zero exit is expected when vulns are found; only fail on empty output.
		if len(output) == 0 {
			if exitErr, ok := err.(*exec.ExitError); ok {
				return nil, fmt.Errorf("exit %d: %s", exitErr.ExitCode(), string(exitErr.Stderr))
			}
			return nil, fmt.Errorf("failed to run: %w", err)
		}
	}

	return parseGovulncheckOutput(output)
}
