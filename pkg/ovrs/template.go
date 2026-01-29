package ovrs

// Template captures the OVRS template schema.
type Template struct {
	ID          string            `yaml:"id" json:"id"`
	Version     string            `yaml:"version" json:"version"`
	Summary     string            `yaml:"summary" json:"summary"`
	Description string            `yaml:"description" json:"description"`
	Metadata    TemplateMetadata  `yaml:"metadata" json:"metadata"`
	Match       MatchCriteria     `yaml:"match" json:"match"`
	Parameters  []Parameter       `yaml:"parameters" json:"parameters"`
	Preflight   []Check           `yaml:"preflight" json:"preflight"`
	Steps       []Step            `yaml:"steps" json:"steps"`
	Validation  []Check           `yaml:"validation" json:"validation"`
	Rollback    *Rollback         `yaml:"rollback,omitempty" json:"rollback,omitempty"`
	Remediation *RemediationHints `yaml:"remediation,omitempty" json:"remediation,omitempty"`
	Extensions  map[string]any    `yaml:"extensions,omitempty" json:"extensions,omitempty"`
	SourcePath  string            `yaml:"-" json:"-"`
}

type TemplateMetadata struct {
	Owner      string   `yaml:"owner" json:"owner"`
	Visibility string   `yaml:"visibility" json:"visibility"`
	Maturity   string   `yaml:"maturity" json:"maturity"`
	Tags       []string `yaml:"tags" json:"tags"`
}

type MatchCriteria struct {
	ResourceKinds        []string          `yaml:"resourceKinds" json:"resourceKinds"`
	OSFamilies           []string          `yaml:"osFamilies" json:"osFamilies"`
	Distributions        []string          `yaml:"distributions" json:"distributions"`
	OSVersionRange       string            `yaml:"osVersionRange" json:"osVersionRange"`
	RequiredPackages     []RequiredPackage `yaml:"requiredPackages" json:"requiredPackages"`
	RequiredCapabilities []string          `yaml:"requiredCapabilities" json:"requiredCapabilities"`
}

type RequiredPackage struct {
	Name string `yaml:"name" json:"name"`
}

type Parameter struct {
	Name        string `yaml:"name" json:"name"`
	Type        string `yaml:"type" json:"type"`
	Required    bool   `yaml:"required" json:"required"`
	Description string `yaml:"description" json:"description"`
}

type Check struct {
	ID     string         `yaml:"id" json:"id"`
	Kind   string         `yaml:"kind" json:"kind"`
	Params map[string]any `yaml:"params" json:"params"`
}

type Step struct {
	ID          string         `yaml:"id" json:"id"`
	Kind        string         `yaml:"kind" json:"kind"`
	DependsOn   []string       `yaml:"dependsOn,omitempty" json:"dependsOn,omitempty"`
	Params      map[string]any `yaml:"params" json:"params"`
	RetryPolicy *RetryPolicy   `yaml:"retryPolicy,omitempty" json:"retryPolicy,omitempty"`
}

type RetryPolicy struct {
	MaxAttempts int `yaml:"maxAttempts" json:"maxAttempts"`
}

type Rollback struct {
	Strategy string `yaml:"strategy" json:"strategy"`
	Steps    []Step `yaml:"steps" json:"steps"`
}

type RemediationHints struct {
	RiskLevel              string   `yaml:"riskLevel" json:"riskLevel"`
	RequiresReboot         bool     `yaml:"requiresReboot" json:"requiresReboot"`
	TypicalDurationSeconds int      `yaml:"typicalDurationSeconds" json:"typicalDurationSeconds"`
	BlastRadiusTags        []string `yaml:"blastRadiusTags" json:"blastRadiusTags"`
	ChangeType             string   `yaml:"changeType" json:"changeType"`
}
