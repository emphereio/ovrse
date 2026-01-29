package plan

// Finding describes a single vulnerability on a host.
type Finding struct {
	CVEID          string `json:"cveId" yaml:"cveId"`
	PackageName    string `json:"packageName" yaml:"packageName"`
	CurrentVersion string `json:"currentVersion,omitempty" yaml:"currentVersion,omitempty"`
}
