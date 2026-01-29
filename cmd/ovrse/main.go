package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/emphereio/ovrse/pkg/inventory"
	"github.com/emphereio/ovrse/pkg/kb"
	"github.com/emphereio/ovrse/pkg/ovrs"
	"github.com/emphereio/ovrse/pkg/plan"
	"gopkg.in/yaml.v3"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	cmd := os.Args[1]
	switch cmd {
	case "validate":
		os.Exit(runValidate(os.Args[2:]))
	case "plan":
		os.Exit(runPlan(os.Args[2:]))
	case "plan-host":
		os.Exit(runPlanHost(os.Args[2:]))
	case "help", "-h", "--help":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n", cmd)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println("Usage: ovrse <command>")
	fmt.Println("Commands:")
	fmt.Println("  validate   Validate example templates and KB files")
	fmt.Println("  plan       Generate a remediation plan for a single CVE and host")
	fmt.Println("  plan-host  Generate remediation actions for a host with multiple findings")
}

func runValidate(args []string) int {
	fs := flag.NewFlagSet("validate", flag.ContinueOnError)
	fs.SetOutput(os.Stdout)
	templateDir := fs.String("templates", filepath.Join("examples", "templates"), "Directory containing OVRS templates")
	kbDir := fs.String("kb", filepath.Join("examples", "kb"), "Directory containing knowledge base YAML files")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	templates, err := ovrs.LoadTemplatesFromDir(*templateDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to load templates: %v\n", err)
		return 1
	}

	var validationFailed bool

	for _, tmpl := range templates {
		if errs := tmpl.Validate(); len(errs) > 0 {
			validationFailed = true
			reportErrors("template", tmpl.ID, tmpl.SourcePath, errs)
		}
	}

	cveMappings, err := kb.LoadCveMappingsFromDir(*kbDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to load CVE mappings: %v\n", err)
		return 1
	}

	for _, mapping := range cveMappings {
		if errs := mapping.Validate(); len(errs) > 0 {
			validationFailed = true
			reportErrors("cve mapping", mapping.CVEID, mapping.SourcePath, errs)
		}
	}

	releases, err := kb.LoadPackageReleasesFromDir(*kbDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to load package releases: %v\n", err)
		return 1
	}

	for _, release := range releases {
		if errs := release.Validate(); len(errs) > 0 {
			validationFailed = true
			reportErrors("package release", fmt.Sprintf("%s %s", release.PackageName, release.Version), release.SourcePath, errs)
		}
	}

	if validationFailed {
		return 1
	}

	fmt.Println("All templates and knowledge base files validated successfully.")
	return 0
}

func runPlan(args []string) int {
	fs := flag.NewFlagSet("plan", flag.ContinueOnError)
	fs.SetOutput(os.Stdout)
	cve := fs.String("cve", "", "CVE identifier to plan for")
	hostID := fs.String("host-id", "host-1", "Identifier for the host")
	osFamily := fs.String("os-family", "", "Operating system family (e.g. debian)")
	distribution := fs.String("distribution", "", "Distribution name (e.g. debian, ubuntu)")
	release := fs.String("release", "", "Distribution release (e.g. 12)")
	arch := fs.String("arch", "", "Architecture (e.g. amd64)")
	packageName := fs.String("package", "", "Installed package name (optional)")
	packageVersion := fs.String("version", "", "Installed package version (optional)")
	templateDir := fs.String("templates-dir", filepath.Join("examples", "templates"), "Directory containing OVRS templates")
	kbDir := fs.String("kb-dir", filepath.Join("examples", "kb"), "Directory containing knowledge base YAML files")
	outputFormat := fs.String("output", "json", "Output format: json or yaml")
	includeRendered := fs.Bool("rendered", false, "Include rendered sections with resolved parameters in the output")
	explain := fs.Bool("explain", false, "Print a human readable summary instead of JSON/YAML output")

	if err := fs.Parse(args); err != nil {
		return 2
	}

	missing := []string{}
	if strings.TrimSpace(*cve) == "" {
		missing = append(missing, "--cve")
	}
	if strings.TrimSpace(*osFamily) == "" {
		missing = append(missing, "--os-family")
	}
	if strings.TrimSpace(*distribution) == "" {
		missing = append(missing, "--distribution")
	}
	if strings.TrimSpace(*release) == "" {
		missing = append(missing, "--release")
	}
	if strings.TrimSpace(*arch) == "" {
		missing = append(missing, "--arch")
	}
	if len(missing) > 0 {
		fmt.Fprintf(os.Stderr, "missing required flags: %s\n", strings.Join(missing, ", "))
		return 2
	}

	if (*packageName == "" && *packageVersion != "") || (*packageName != "" && *packageVersion == "") {
		fmt.Fprintln(os.Stderr, "--package and --version must be provided together")
		return 2
	}

	host := inventory.Host{
		ID:           *hostID,
		OSFamily:     *osFamily,
		Distribution: *distribution,
		Release:      *release,
		Architecture: *arch,
	}
	if *packageName != "" {
		host.Packages = map[string]string{
			*packageName: *packageVersion,
		}
	}

	templates, err := ovrs.LoadTemplatesFromDir(*templateDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to load templates: %v\n", err)
		return 1
	}

	cveMappings, err := kb.LoadCveMappingsFromDir(*kbDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to load CVE mappings: %v\n", err)
		return 1
	}

	releases, err := kb.LoadPackageReleasesFromDir(*kbDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to load package releases: %v\n", err)
		return 1
	}

	planner := plan.Planner{
		Templates:       templates,
		CveMappings:     cveMappings,
		PackageReleases: releases,
	}

	result, err := planner.PlanForSingleCVE(plan.PlanOptions{
		CVEID: *cve,
		Host:  host,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "unable to create plan: %v\n", err)
		return 1
	}

	if *explain {
		printPlanExplanation(result)
		return 0
	}

	if !*includeRendered {
		result.RenderedPreflight = nil
		result.RenderedSteps = nil
		result.RenderedValidation = nil
		result.RenderWarnings = nil
	}

	switch strings.ToLower(*outputFormat) {
	case "json":
		data, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to encode JSON: %v\n", err)
			return 1
		}
		fmt.Println(string(data))
	case "yaml", "yml":
		data, err := yaml.Marshal(result)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to encode YAML: %v\n", err)
			return 1
		}
		fmt.Println(string(data))
	default:
		fmt.Fprintf(os.Stderr, "unknown output format %q (use json or yaml)\n", *outputFormat)
		return 2
	}

	return 0
}

func runPlanHost(args []string) int {
	fs := flag.NewFlagSet("plan-host", flag.ContinueOnError)
	fs.SetOutput(os.Stdout)
	hostFile := fs.String("host-file", "", "Path to JSON file describing the host inventory")
	findingsFile := fs.String("findings-file", "", "Path to JSON file containing findings")
	templateDir := fs.String("templates-dir", filepath.Join("examples", "templates"), "Directory containing OVRS templates")
	kbDir := fs.String("kb-dir", filepath.Join("examples", "kb"), "Directory containing knowledge base YAML files")
	outputFormat := fs.String("output", "json", "Output format: json or yaml")
	explain := fs.Bool("explain", false, "Print a human readable summary")

	if err := fs.Parse(args); err != nil {
		return 2
	}

	if strings.TrimSpace(*hostFile) == "" || strings.TrimSpace(*findingsFile) == "" {
		fmt.Fprintln(os.Stderr, "--host-file and --findings-file are required")
		return 2
	}

	var host inventory.Host
	if err := readJSONFile(*hostFile, &host); err != nil {
		fmt.Fprintf(os.Stderr, "failed to read host file: %v\n", err)
		return 1
	}

	var findings []plan.Finding
	if err := readJSONFile(*findingsFile, &findings); err != nil {
		fmt.Fprintf(os.Stderr, "failed to read findings file: %v\n", err)
		return 1
	}

	templates, err := ovrs.LoadTemplatesFromDir(*templateDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to load templates: %v\n", err)
		return 1
	}
	cveMappings, err := kb.LoadCveMappingsFromDir(*kbDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to load CVE mappings: %v\n", err)
		return 1
	}
	releases, err := kb.LoadPackageReleasesFromDir(*kbDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to load package releases: %v\n", err)
		return 1
	}

	planner := plan.Planner{
		Templates:       templates,
		CveMappings:     cveMappings,
		PackageReleases: releases,
	}

	hostPlan, err := planner.PlanForHostFindings(plan.HostPlanOptions{
		Host:     host,
		Findings: findings,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "unable to create host plan: %v\n", err)
		return 1
	}

	if *explain {
		printHostPlanExplanation(hostPlan)
		return 0
	}

	switch strings.ToLower(*outputFormat) {
	case "json":
		data, err := json.MarshalIndent(hostPlan, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to encode JSON: %v\n", err)
			return 1
		}
		fmt.Println(string(data))
	case "yaml", "yml":
		data, err := yaml.Marshal(hostPlan)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to encode YAML: %v\n", err)
			return 1
		}
		fmt.Println(string(data))
	default:
		fmt.Fprintf(os.Stderr, "unknown output format %q (use json or yaml)\n", *outputFormat)
		return 2
	}

	return 0
}

func reportErrors(kind, identifier, path string, errs []error) {
	if identifier == "" {
		identifier = "(unknown)"
	}
	if path == "" {
		path = "(unknown file)"
	}

	fmt.Fprintf(os.Stderr, "%s %s in %s has %d error(s):\n", kind, identifier, path, len(errs))
	for _, err := range errs {
		fmt.Fprintf(os.Stderr, "  - %v\n", err)
	}
}

func printPlanExplanation(plan *plan.Plan) {
	fmt.Printf("Plan for %s on host %s\n\n", plan.CVEID, plan.Host.ID)
	fmt.Printf("  Template:        %s\n", plan.TemplateID)
	fmt.Printf("  Target package:  %s\n", fallback(plan.TargetPackage, "(unknown)"))
	fmt.Printf("  Current version: %s\n", fallback(plan.CurrentVersion, "(unknown)"))
	fmt.Printf("  Target version:  %s\n", fallback(plan.TargetVersion, "(unknown)"))

	if len(plan.FixedCVEs) > 0 {
		fmt.Printf("\n  CVEs that will be fixed by this upgrade (%s):\n", plan.FixedCVEsSource)
		for _, cve := range plan.FixedCVEs {
			fmt.Printf("    - %s\n", cve)
		}
	} else {
		fmt.Println("\n  No fixed CVEs were found in package-release metadata for this package/version.")
	}
}

func fallback(val, defaultVal string) string {
	if strings.TrimSpace(val) == "" {
		return defaultVal
	}
	return val
}

func printHostPlanExplanation(hp *plan.HostPlan) {
	fmt.Printf("Plan for host %s\n\n", fallback(hp.Host.ID, "(unknown)"))
	fmt.Printf("  Total findings:      %d\n", hp.Summary.TotalFindings)
	fmt.Printf("  Actions:             %d\n", hp.Summary.ActionsCount)
	fmt.Printf("  Distinct CVEs fixed: %d\n", hp.Summary.DistinctCVEsFixed)

	if len(hp.Actions) == 0 {
		fmt.Println("\n  No actionable templates were found for the provided findings.")
		return
	}

	for idx, action := range hp.Actions {
		fmt.Printf("\n  Action %d:\n", idx+1)
		fmt.Printf("    Template:        %s\n", fallback(action.TemplateID, "(unknown)"))
		fmt.Printf("    Package:         %s\n", fallback(action.TargetPackage, "(unknown)"))
		fmt.Printf("    Current version: %s\n", fallback(action.CurrentVersion, "(unknown)"))
		fmt.Printf("    Target version:  %s\n", fallback(action.TargetVersion, "(unknown)"))
		if len(action.FixedCVEs) > 0 {
			fmt.Println("    Fixed CVEs:")
			for _, cve := range action.FixedCVEs {
				fmt.Printf("      - %s\n", cve)
			}
		} else {
			fmt.Println("    Fixed CVEs: (unknown)")
		}
	}
}

func readJSONFile(path string, v any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, v)
}
