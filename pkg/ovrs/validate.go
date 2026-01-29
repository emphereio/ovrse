package ovrs

import "fmt"

// Validate performs basic structural validation on the template.
func (t *Template) Validate() []error {
	var errs []error

	if t.ID == "" {
		errs = append(errs, fmt.Errorf("template id is required"))
	}
	if t.Version == "" {
		errs = append(errs, fmt.Errorf("template version is required"))
	}
	if t.Summary == "" {
		errs = append(errs, fmt.Errorf("template summary is required"))
	}
	if len(t.Match.ResourceKinds) == 0 {
		errs = append(errs, fmt.Errorf("match.resourceKinds must have at least one entry"))
	}

	errs = append(errs, validateParameters(t.Parameters)...)
	errs = append(errs, validateChecks("preflight", t.Preflight)...)
	errs = append(errs, validateSteps("steps", t.Steps)...)
	errs = append(errs, validateChecks("validation", t.Validation)...)

	if t.Rollback != nil {
		if t.Rollback.Strategy == "" {
			errs = append(errs, fmt.Errorf("rollback.strategy is required when rollback is defined"))
		}
		errs = append(errs, validateSteps("rollback.steps", t.Rollback.Steps)...)
	}

	return errs
}

func validateParameters(params []Parameter) []error {
	var errs []error
	names := make(map[string]int)
	for idx, p := range params {
		if p.Name == "" {
			errs = append(errs, fmt.Errorf("parameters[%d]: name is required", idx))
			continue
		}
		if prev, exists := names[p.Name]; exists {
			errs = append(errs, fmt.Errorf("parameters[%d]: duplicate name %q (already used at index %d)", idx, p.Name, prev))
			continue
		}
		names[p.Name] = idx
	}
	return errs
}

func validateChecks(section string, checks []Check) []error {
	var errs []error
	ids := make(map[string]int)
	for idx, c := range checks {
		if c.ID == "" {
			errs = append(errs, fmt.Errorf("%s[%d]: id is required", section, idx))
			continue
		}
		if prev, exists := ids[c.ID]; exists {
			errs = append(errs, fmt.Errorf("%s[%d]: duplicate id %q (already used at index %d)", section, idx, c.ID, prev))
			continue
		}
		ids[c.ID] = idx
	}
	return errs
}

func validateSteps(section string, steps []Step) []error {
	var errs []error
	ids := make(map[string]int)
	for idx, s := range steps {
		if s.ID == "" {
			errs = append(errs, fmt.Errorf("%s[%d]: id is required", section, idx))
			continue
		}
		if prev, exists := ids[s.ID]; exists {
			errs = append(errs, fmt.Errorf("%s[%d]: duplicate id %q (already used at index %d)", section, idx, s.ID, prev))
			continue
		}
		ids[s.ID] = idx
	}

	for idx, s := range steps {
		for _, dep := range s.DependsOn {
			if _, ok := ids[dep]; !ok {
				errs = append(errs, fmt.Errorf("%s[%d]: dependsOn references unknown step %q", section, idx, dep))
			}
		}
	}
	return errs
}
