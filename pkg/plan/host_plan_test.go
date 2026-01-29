package plan_test

import (
	"testing"

	"github.com/emphereio/ovrse/pkg/inventory"
	"github.com/emphereio/ovrse/pkg/kb"
	"github.com/emphereio/ovrse/pkg/ovrs"
	"github.com/emphereio/ovrse/pkg/plan"
)

func TestPlanForHostFindings(t *testing.T) {
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

	findings := []plan.Finding{
		{CVEID: "CVE-2025-1234", PackageName: "nginx"},
		{CVEID: "CVE-2025-5678", PackageName: "nginx"},
	}

	hostPlan, err := planner.PlanForHostFindings(plan.HostPlanOptions{
		Host:     host,
		Findings: findings,
	})
	if err != nil {
		t.Fatalf("PlanForHostFindings failed: %v", err)
	}

	if len(hostPlan.Actions) != 1 {
		t.Fatalf("expected 1 action, got %d", len(hostPlan.Actions))
	}
	action := hostPlan.Actions[0]
	if action.TargetPackage != "nginx" {
		t.Fatalf("expected TargetPackage nginx, got %s", action.TargetPackage)
	}
	if action.TargetVersion != "1.24.0" {
		t.Fatalf("expected TargetVersion 1.24.0, got %s", action.TargetVersion)
	}
	if len(action.FixedCVEs) < 2 {
		t.Fatalf("expected at least 2 fixed CVEs, got %v", action.FixedCVEs)
	}
	if hostPlan.Summary.TotalFindings != len(findings) {
		t.Fatalf("expected TotalFindings %d, got %d", len(findings), hostPlan.Summary.TotalFindings)
	}
	if hostPlan.Summary.ActionsCount != 1 {
		t.Fatalf("expected ActionsCount 1, got %d", hostPlan.Summary.ActionsCount)
	}
}
