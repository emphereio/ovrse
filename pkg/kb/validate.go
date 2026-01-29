package kb

import "fmt"

// Validate ensures the CVE mapping has required fields.
func (m *CveMapping) Validate() []error {
	var errs []error
	if m.CVEID == "" {
		errs = append(errs, fmt.Errorf("cveId is required"))
	}
	if m.TemplateID == "" {
		errs = append(errs, fmt.Errorf("templateId is required"))
	}
	if m.Parameters == nil {
		errs = append(errs, fmt.Errorf("parameters must be provided (can be empty)"))
	}
	if m.Source.Kind == "" {
		errs = append(errs, fmt.Errorf("source.kind is required"))
	}
	if m.Source.ImportedAt == "" {
		errs = append(errs, fmt.Errorf("source.importedAt is required"))
	}
	return errs
}

// Validate ensures the package release has required fields.
func (p *PackageRelease) Validate() []error {
	var errs []error
	if p.OSFamily == "" {
		errs = append(errs, fmt.Errorf("osFamily is required"))
	}
	if p.Distribution == "" {
		errs = append(errs, fmt.Errorf("distribution is required"))
	}
	if p.PackageName == "" {
		errs = append(errs, fmt.Errorf("packageName is required"))
	}
	if p.Version == "" {
		errs = append(errs, fmt.Errorf("version is required"))
	}
	if len(p.FixesCVEs) == 0 {
		errs = append(errs, fmt.Errorf("fixesCves must include at least one cve"))
	}
	if p.Source.Kind == "" {
		errs = append(errs, fmt.Errorf("source.kind is required"))
	}
	return errs
}
