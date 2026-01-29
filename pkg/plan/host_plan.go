package plan

import "github.com/emphereio/ovrse/pkg/inventory"

// ActionPlan summarizes a single remediation action on a host.
type ActionPlan struct {
	TemplateID     string   `json:"templateId" yaml:"templateId"`
	TargetPackage  string   `json:"targetPackage" yaml:"targetPackage"`
	CurrentVersion string   `json:"currentVersion,omitempty" yaml:"currentVersion,omitempty"`
	TargetVersion  string   `json:"targetVersion,omitempty" yaml:"targetVersion,omitempty"`
	FixedCVEs      []string `json:"fixedCves,omitempty" yaml:"fixedCves,omitempty"`
}

// HostPlanSummary captures counts for a host plan.
type HostPlanSummary struct {
	TotalFindings     int `json:"totalFindings" yaml:"totalFindings"`
	DistinctCVEsFixed int `json:"distinctCvesFixed" yaml:"distinctCvesFixed"`
	ActionsCount      int `json:"actionsCount" yaml:"actionsCount"`
}

// HostPlan contains all remediation actions for a host.
type HostPlan struct {
	Host    inventory.Host  `json:"host" yaml:"host"`
	Actions []ActionPlan    `json:"actions" yaml:"actions"`
	Summary HostPlanSummary `json:"summary" yaml:"summary"`
}
