package plan

import (
	"fmt"
	"sort"
	"strings"

	"github.com/emphereio/ovrse/pkg/inventory"
	"github.com/emphereio/ovrse/pkg/kb"
	"github.com/emphereio/ovrse/pkg/ovrs"
	"github.com/emphereio/ovrse/pkg/render"
)

// Planner provides simple plan generation over in-memory data.
type Planner struct {
	Templates       []*ovrs.Template
	CveMappings     []*kb.CveMapping
	PackageReleases []*kb.PackageRelease
}

// PlanOptions captures the request to plan a single CVE for a host.
type PlanOptions struct {
	CVEID string
	Host  inventory.Host
}

// HostPlanOptions describes a host level planning request.
type HostPlanOptions struct {
	Host     inventory.Host
	Findings []Finding
}

// PlanForSingleCVE finds the first matching mapping/template and produces a plan.
func (p *Planner) PlanForSingleCVE(opts PlanOptions) (*Plan, error) {
	if strings.TrimSpace(opts.CVEID) == "" {
		return nil, fmt.Errorf("cve id is required")
	}

	mapping := p.findMapping(opts.CVEID, opts.Host)
	if mapping == nil {
		return nil, fmt.Errorf("no CVE mappings found for %s on host %s", opts.CVEID, opts.Host.ID)
	}

	template := p.findTemplate(mapping.TemplateID)
	if template == nil {
		return nil, fmt.Errorf("template %s referenced by mapping not found", mapping.TemplateID)
	}

	params := mapping.Parameters
	if params == nil {
		params = map[string]any{}
	}

	targetPackage, _ := params["targetPackage"].(string)
	targetVersion, _ := params["targetVersion"].(string)
	currentVersion := ""
	if targetPackage != "" && opts.Host.Packages != nil {
		if v, ok := opts.Host.Packages[targetPackage]; ok {
			currentVersion = v
		}
	}

	fixedCVEs := []string{}
	if targetPackage != "" && targetVersion != "" {
		fixedCVEs = computeFixedCVEsForPackage(opts.Host, targetPackage, targetVersion, p.PackageReleases)
	}

	result := &Plan{
		CVEID:          opts.CVEID,
		TemplateID:     template.ID,
		Host:           opts.Host,
		Parameters:     params,
		Steps:          template.Steps,
		Preflight:      template.Preflight,
		Validation:     template.Validation,
		TargetPackage:  targetPackage,
		CurrentVersion: currentVersion,
		TargetVersion:  targetVersion,
		FixedCVEs:      fixedCVEs,
	}
	if len(fixedCVEs) > 0 {
		result.FixedCVEsSource = "package-release"
	}

	rendered, renderErrs := render.RenderTemplateSections(template, render.RenderContext{
		Host:       opts.Host,
		Parameters: params,
	})
	result.RenderedPreflight = rendered.Preflight
	result.RenderedSteps = rendered.Steps
	result.RenderedValidation = rendered.Validation
	for _, rErr := range renderErrs {
		result.RenderWarnings = append(result.RenderWarnings, rErr.Error())
	}

	return result, nil
}

// PlanForHostFindings groups findings by package and creates package-level actions.
func (p *Planner) PlanForHostFindings(opts HostPlanOptions) (*HostPlan, error) {
	hostPlan := &HostPlan{
		Host: opts.Host,
	}

	if len(opts.Findings) == 0 {
		hostPlan.Summary = HostPlanSummary{}
		return hostPlan, nil
	}

	byPackage := make(map[string][]Finding)
	for _, f := range opts.Findings {
		if strings.TrimSpace(f.PackageName) == "" || strings.TrimSpace(f.CVEID) == "" {
			continue
		}
		byPackage[f.PackageName] = append(byPackage[f.PackageName], f)
	}

	distinctFixed := make(map[string]struct{})

	for pkgName, findings := range byPackage {
		cveSet := make(map[string]struct{})
		for _, f := range findings {
			cveSet[f.CVEID] = struct{}{}
		}

		var templateID string
		targetPackage := pkgName
		targetVersion := ""

		for cve := range cveSet {
			mapping := p.findMappingForPackage(cve, opts.Host, pkgName)
			if mapping == nil {
				continue
			}
			if templateID == "" {
				templateID = mapping.TemplateID
			}
			if mapping.Parameters != nil {
				if tp, ok := mapping.Parameters["targetPackage"].(string); ok && tp != "" {
					targetPackage = tp
				}
				if tv, ok := mapping.Parameters["targetVersion"].(string); ok && tv != "" {
					targetVersion = pickHigherVersion(targetVersion, tv)
				}
			}
		}

		if templateID == "" {
			continue
		}

		currentVersion := ""
		if opts.Host.Packages != nil {
			if v, ok := opts.Host.Packages[targetPackage]; ok {
				currentVersion = v
			}
		}
		if currentVersion == "" {
			for _, f := range findings {
				if f.CurrentVersion != "" {
					currentVersion = f.CurrentVersion
					break
				}
			}
		}

		fixed := computeFixedCVEsForPackage(opts.Host, targetPackage, targetVersion, p.PackageReleases)
		if len(fixed) == 0 {
			fixed = sortedKeys(cveSet)
		}
		for _, cve := range fixed {
			distinctFixed[cve] = struct{}{}
		}

		action := ActionPlan{
			TemplateID:     templateID,
			TargetPackage:  targetPackage,
			CurrentVersion: currentVersion,
			TargetVersion:  targetVersion,
			FixedCVEs:      fixed,
		}
		hostPlan.Actions = append(hostPlan.Actions, action)
	}

	hostPlan.Summary = HostPlanSummary{
		TotalFindings:     len(opts.Findings),
		DistinctCVEsFixed: len(distinctFixed),
		ActionsCount:      len(hostPlan.Actions),
	}

	return hostPlan, nil
}

func (p *Planner) findMapping(cve string, host inventory.Host) *kb.CveMapping {
	for _, mapping := range p.CveMappings {
		if !strings.EqualFold(mapping.CVEID, cve) {
			continue
		}
		if applicabilityMatches(mapping.Applicability, host) {
			return mapping
		}
	}
	return nil
}

func (p *Planner) findMappingForPackage(cve string, host inventory.Host, pkgName string) *kb.CveMapping {
	for _, mapping := range p.CveMappings {
		if !strings.EqualFold(mapping.CVEID, cve) {
			continue
		}
		if !applicabilityMatches(mapping.Applicability, host) {
			continue
		}
		if mapping.Parameters != nil {
			if tp, ok := mapping.Parameters["targetPackage"].(string); ok && tp != "" && !strings.EqualFold(tp, pkgName) {
				continue
			}
		}
		return mapping
	}
	return nil
}

func (p *Planner) findTemplate(id string) *ovrs.Template {
	for _, tmpl := range p.Templates {
		if tmpl.ID == id {
			return tmpl
		}
	}
	return nil
}

// applicabilityMatches tests whether the host satisfies the mapping's applicability.
// For ecosystem packages (npm, pypi, etc.), applicability is checked via the Ecosystems field.
// For OS-level packages, OSFamilies, Distributions, and Architectures are used.
func applicabilityMatches(a kb.Applicability, host inventory.Host) bool {
	// Ecosystem-level applicability: if ecosystems are specified, this mapping is for
	// application-level packages. Skip OS-level checks if host has no OS context.
	// Future: Add Ecosystem field to Host for application-level inventory.
	if len(a.Ecosystems) > 0 {
		// If this is an ecosystem-specific mapping but we're matching against a host,
		// only match if no OS constraints are specified (pure ecosystem mapping).
		// Otherwise, treat as OS-level mapping that also specifies ecosystem context.
		if len(a.OSFamilies) == 0 && len(a.Distributions) == 0 && host.OSFamily == "" {
			// Pure ecosystem mapping against non-OS context - allow match
			return true
		}
	}

	// OS-level applicability checks
	if len(a.OSFamilies) > 0 && !containsIgnoreCase(a.OSFamilies, host.OSFamily) {
		return false
	}
	if len(a.Distributions) > 0 && !containsIgnoreCase(a.Distributions, host.Distribution) {
		return false
	}
	if len(a.Architectures) > 0 && !containsIgnoreCase(a.Architectures, host.Architecture) {
		return false
	}
	if strings.TrimSpace(a.OSVersionRange) != "" && !releaseMatchesRange(host.Release, a.OSVersionRange) {
		return false
	}
	return true
}

func containsIgnoreCase(values []string, target string) bool {
	for _, v := range values {
		if strings.EqualFold(v, target) {
			return true
		}
	}
	return false
}

func releaseMatchesRange(release, constraint string) bool {
	if strings.TrimSpace(constraint) == "" {
		return true
	}
	if strings.TrimSpace(release) == "" {
		return false
	}

	constraint = strings.TrimSpace(constraint)
	release = strings.TrimSpace(release)

	switch {
	case strings.HasPrefix(constraint, ">="):
		return compareNumericStrings(release, strings.TrimSpace(constraint[2:])) >= 0
	case strings.HasPrefix(constraint, "<="):
		return compareNumericStrings(release, strings.TrimSpace(constraint[2:])) <= 0
	case strings.HasPrefix(constraint, ">"):
		return compareNumericStrings(release, strings.TrimSpace(constraint[1:])) > 0
	case strings.HasPrefix(constraint, "<"):
		return compareNumericStrings(release, strings.TrimSpace(constraint[1:])) < 0
	default:
		return strings.EqualFold(release, constraint)
	}
}

func compareNumericStrings(a, b string) int {
	ai, aErr := parseInt(a)
	bi, bErr := parseInt(b)
	if aErr == nil && bErr == nil {
		switch {
		case ai < bi:
			return -1
		case ai > bi:
			return 1
		default:
			return 0
		}
	}
	return strings.Compare(a, b)
}

func parseInt(val string) (int, error) {
	var n int
	for i := 0; i < len(val); i++ {
		if val[i] < '0' || val[i] > '9' {
			return 0, fmt.Errorf("non digit")
		}
		n = n*10 + int(val[i]-'0')
	}
	return n, nil
}

// computeFixedCVEsForPackage returns CVEs fixed by upgrading to targetVersion.
// Supports both OS-level packages (matched by OSFamily/Distribution) and
// ecosystem packages (matched by Ecosystem field).
func computeFixedCVEsForPackage(host inventory.Host, packageName, targetVersion string, releases []*kb.PackageRelease) []string {
	if packageName == "" || targetVersion == "" {
		return nil
	}

	cves := make(map[string]struct{})
	for _, rel := range releases {
		if !strings.EqualFold(rel.PackageName, packageName) {
			continue
		}
		if rel.Version != targetVersion {
			continue
		}

		// Match based on context type:
		// - If release has Ecosystem but no OSFamily, it's an ecosystem package (npm, pypi, etc.)
		// - If release has OSFamily, it's an OS-level package
		if rel.Ecosystem != "" && rel.OSFamily == "" {
			// Ecosystem package - no OS-level matching needed
			// Future: could add ecosystem matching when Host supports it
		} else {
			// OS-level package - match by OS context
			if !strings.EqualFold(rel.OSFamily, host.OSFamily) {
				continue
			}
			if rel.Distribution != "" && !strings.EqualFold(rel.Distribution, host.Distribution) {
				continue
			}
			if rel.Architecture != "" && host.Architecture != "" && !strings.EqualFold(rel.Architecture, host.Architecture) {
				continue
			}
		}

		for _, cve := range rel.FixesCVEs {
			if cve == "" {
				continue
			}
			cves[cve] = struct{}{}
		}
	}

	if len(cves) == 0 {
		return nil
	}

	result := make([]string, 0, len(cves))
	for cve := range cves {
		result = append(result, cve)
	}
	sort.Strings(result)
	return result
}

func pickHigherVersion(current, candidate string) string {
	if candidate == "" {
		return current
	}
	if current == "" {
		return candidate
	}
	if strings.Compare(current, candidate) >= 0 {
		return current
	}
	return candidate
}

func sortedKeys(set map[string]struct{}) []string {
	if len(set) == 0 {
		return nil
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
