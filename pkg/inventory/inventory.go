package inventory

// Host represents a compute target and its minimal attributes.
type Host struct {
	ID           string            `json:"id" yaml:"id"`
	OSFamily     string            `json:"osFamily" yaml:"osFamily"`
	Distribution string            `json:"distribution" yaml:"distribution"`
	Release      string            `json:"release" yaml:"release"`
	Architecture string            `json:"architecture" yaml:"architecture"`
	Packages     map[string]string `json:"packages" yaml:"packages"`
}
