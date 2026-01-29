package plan_test

import (
	"testing"

	"github.com/emphereio/ovrse/pkg/inventory"
	"github.com/emphereio/ovrse/pkg/kb"
	"github.com/emphereio/ovrse/pkg/ovrs"
	"github.com/emphereio/ovrse/pkg/plan"
)

func TestPlanForSingleCVE(t *testing.T) {
	templateDir := repoPath("examples", "templates")
	kbDir := repoPath("examples", "kb")

	templates, err := ovrs.LoadTemplatesFromDir(templateDir)
	if err != nil {
		t.Fatalf("LoadTemplatesFromDir failed: %v", err)
	}
	cveMappings, err := kb.LoadCveMappingsFromDir(kbDir)
	if err != nil {
		t.Fatalf("LoadCveMappingsFromDir failed: %v", err)
	}
	releases, err := kb.LoadPackageReleasesFromDir(kbDir)
	if err != nil {
		t.Fatalf("LoadPackageReleasesFromDir failed: %v", err)
	}

	planner := plan.Planner{
		Templates:       templates,
		CveMappings:     cveMappings,
		PackageReleases: releases,
	}

	host := inventory.Host{
		ID:           "host-abc",
		OSFamily:     "debian",
		Distribution: "debian",
		Release:      "12",
		Architecture: "amd64",
		Packages: map[string]string{
			"nginx": "1.22.0",
		},
	}

	result, err := planner.PlanForSingleCVE(plan.PlanOptions{
		CVEID: "CVE-2025-1234",
		Host:  host,
	})
	if err != nil {
		t.Fatalf("PlanForSingleCVE failed: %v", err)
	}
	if result.TemplateID != "os.debian.package-upgrade.nginx" {
		t.Fatalf("expected template ID os.debian.package-upgrade.nginx, got %s", result.TemplateID)
	}
	if result.Parameters["targetPackage"] != "nginx" {
		t.Fatalf("expected targetPackage=nginx, got %v", result.Parameters["targetPackage"])
	}
	if len(result.Steps) == 0 {
		t.Fatalf("expected steps to be populated")
	}
	if len(result.RenderedSteps) == 0 {
		t.Fatalf("expected rendered steps to be populated")
	}

	foundPackage := false
	for _, step := range result.RenderedSteps {
		if val, ok := step.Params["package"]; ok {
			if val != "nginx" {
				t.Fatalf("expected rendered package param to be nginx, got %v", val)
			}
			foundPackage = true
			break
		}
	}
	if !foundPackage {
		t.Fatalf("expected rendered steps to include package parameter")
	}

	if result.TargetPackage != "nginx" {
		t.Fatalf("expected TargetPackage nginx, got %s", result.TargetPackage)
	}
	if result.TargetVersion != "1.24.0" {
		t.Fatalf("expected TargetVersion 1.24.0, got %s", result.TargetVersion)
	}
	if result.CurrentVersion != "1.22.0" {
		t.Fatalf("expected CurrentVersion 1.22.0, got %s", result.CurrentVersion)
	}
	if len(result.FixedCVEs) == 0 {
		t.Fatalf("expected FixedCVEs to be populated")
	}
	if result.FixedCVEsSource != "package-release" {
		t.Fatalf("expected FixedCVEsSource package-release, got %s", result.FixedCVEsSource)
	}
	var hasTargetCVE bool
	for _, cve := range result.FixedCVEs {
		if cve == "CVE-2025-1234" {
			hasTargetCVE = true
			break
		}
	}
	if !hasTargetCVE {
		t.Fatalf("expected FixedCVEs to include CVE-2025-1234, got %v", result.FixedCVEs)
	}
}
