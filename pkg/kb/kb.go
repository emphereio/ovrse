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
	Ecosystems     []string `yaml:"ecosystems" json:"ecosystems"`
	OSFamilies     []string `yaml:"osFamilies" json:"osFamilies"`
	Distributions  []string `yaml:"distributions" json:"distributions"`
	OSVersionRange string   `yaml:"osVersionRange" json:"osVersionRange"`
	Architectures  []string `yaml:"architectures" json:"architectures"`
}

type SourceInfo struct {
	Kind       string `yaml:"kind" json:"kind"`
	Reference  string `yaml:"reference" json:"reference"`
	ImportedAt string `yaml:"importedAt" json:"importedAt"`
}

// Dependency represents a direct dependency of a package version.
// Used for transitive shadow analysis.
type Dependency struct {
	Name      string `yaml:"name" json:"name"`
	Version   string `yaml:"version" json:"version"`
	Ecosystem string `yaml:"ecosystem" json:"ecosystem"`
}

type PackageRelease struct {
	PackageName  string       `yaml:"packageName" json:"packageName"`
	Version      string       `yaml:"version" json:"version"`
	Ecosystem    string       `yaml:"ecosystem" json:"ecosystem"`
	OSFamily     string       `yaml:"osFamily" json:"osFamily"`
	Distribution string       `yaml:"distribution" json:"distribution"`
	Release      string       `yaml:"release" json:"release"`
	Architecture string       `yaml:"architecture" json:"architecture"`
	FixesCVEs    []string     `yaml:"fixesCves" json:"fixesCves"`
	HasCVEs      []string     `yaml:"hasCves" json:"hasCves"`
	Dependencies []Dependency `yaml:"dependencies" json:"dependencies"`
	Source       SourceInfo   `yaml:"source" json:"source"`
	SourcePath   string       `yaml:"-" json:"-"`
}
