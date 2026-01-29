package plan

import (
	"github.com/emphereio/ovrse/pkg/inventory"
	"github.com/emphereio/ovrse/pkg/ovrs"
)

// Plan is a minimal rendering of how to remediate a CVE on a host.
type Plan struct {
	CVEID      string         `json:"cveId" yaml:"cveId"`
	TemplateID string         `json:"templateId" yaml:"templateId"`
	Host       inventory.Host `json:"host" yaml:"host"`
	Parameters map[string]any `json:"parameters" yaml:"parameters"`

	Preflight  []ovrs.Check `json:"preflight" yaml:"preflight"`
	Steps      []ovrs.Step  `json:"steps" yaml:"steps"`
	Validation []ovrs.Check `json:"validation" yaml:"validation"`

	RenderedPreflight  []ovrs.Check `json:"renderedPreflight,omitempty" yaml:"renderedPreflight,omitempty"`
	RenderedSteps      []ovrs.Step  `json:"renderedSteps,omitempty" yaml:"renderedSteps,omitempty"`
	RenderedValidation []ovrs.Check `json:"renderedValidation,omitempty" yaml:"renderedValidation,omitempty"`

	RenderWarnings []string `json:"renderWarnings,omitempty" yaml:"renderWarnings,omitempty"`

	TargetPackage   string   `json:"targetPackage,omitempty" yaml:"targetPackage,omitempty"`
	CurrentVersion  string   `json:"currentVersion,omitempty" yaml:"currentVersion,omitempty"`
	TargetVersion   string   `json:"targetVersion,omitempty" yaml:"targetVersion,omitempty"`
	FixedCVEs       []string `json:"fixedCves,omitempty" yaml:"fixedCves,omitempty"`
	FixedCVEsSource string   `json:"fixedCvesSource,omitempty" yaml:"fixedCvesSource,omitempty"`
}
