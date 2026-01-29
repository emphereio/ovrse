package kb

type CveMapping struct {
	CVEID        string        `yaml:"cveId" json:"cveId"`
	TemplateID   string        `yaml:"templateId" json:"templateId"`
	Parameters   map[string]any `yaml:"parameters" json:"parameters"`
	Applicability Applicability `yaml:"applicability" json:"applicability"`
	Notes        string        `yaml:"notes" json:"notes"`
	Source       SourceInfo    `yaml:"source" json:"source"`
	SourcePath   string        `yaml:"-" json:"-"`
}

type Applicability struct {
	OSFamilies    []string `yaml:"osFamilies" json:"osFamilies"`
	Distributions []string `yaml:"distributions" json:"distributions"`
	OSVersionRange string  `yaml:"osVersionRange" json:"osVersionRange"`
	Architectures []string `yaml:"architectures" json:"architectures"`
}

type SourceInfo struct {
	Kind       string `yaml:"kind" json:"kind"`
	Reference  string `yaml:"reference" json:"reference"`
	ImportedAt string `yaml:"importedAt" json:"importedAt"`
}

type PackageRelease struct {
	OSFamily     string     `yaml:"osFamily" json:"osFamily"`
	Distribution string     `yaml:"distribution" json:"distribution"`
	Release      string     `yaml:"release" json:"release"`
	Architecture string     `yaml:"architecture" json:"architecture"`
	PackageName  string     `yaml:"packageName" json:"packageName"`
	Version      string     `yaml:"version" json:"version"`
	FixesCVEs    []string   `yaml:"fixesCves" json:"fixesCves"`
	Source       SourceInfo `yaml:"source" json:"source"`
	SourcePath   string     `yaml:"-" json:"-"`
}
