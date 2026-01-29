package render

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/emphereio/ovrse/pkg/inventory"
	"github.com/emphereio/ovrse/pkg/ovrs"
)

// RenderContext carries the data required to substitute template placeholders.
type RenderContext struct {
	Host       inventory.Host
	Parameters map[string]any
}

// RenderedPlanSections contains rendered template sections.
type RenderedPlanSections struct {
	Preflight  []ovrs.Check
	Steps      []ovrs.Step
	Validation []ovrs.Check
}

var placeholderPattern = regexp.MustCompile(`\{\{\s*([^}]+?)\s*\}\}`)

// RenderTemplateSections applies placeholder substitution to template sections.
func RenderTemplateSections(t *ovrs.Template, ctx RenderContext) (RenderedPlanSections, []error) {
	var allErrs []error

	preflight := copyChecks(t.Preflight)
	for i := range preflight {
		value, errs := recursivelySubstitute(preflight[i].Params, ctx)
		if len(errs) > 0 {
			allErrs = append(allErrs, errs...)
		}
		if params, ok := value.(map[string]any); ok {
			preflight[i].Params = params
		}
	}

	steps := copySteps(t.Steps)
	for i := range steps {
		value, errs := recursivelySubstitute(steps[i].Params, ctx)
		if len(errs) > 0 {
			allErrs = append(allErrs, errs...)
		}
		if params, ok := value.(map[string]any); ok {
			steps[i].Params = params
		}
	}

	validation := copyChecks(t.Validation)
	for i := range validation {
		value, errs := recursivelySubstitute(validation[i].Params, ctx)
		if len(errs) > 0 {
			allErrs = append(allErrs, errs...)
		}
		if params, ok := value.(map[string]any); ok {
			validation[i].Params = params
		}
	}

	return RenderedPlanSections{
		Preflight:  preflight,
		Steps:      steps,
		Validation: validation,
	}, allErrs
}

func copyChecks(src []ovrs.Check) []ovrs.Check {
	if len(src) == 0 {
		return nil
	}
	out := make([]ovrs.Check, len(src))
	for i, check := range src {
		out[i] = check
		out[i].Params = copyMap(check.Params)
	}
	return out
}

func copySteps(src []ovrs.Step) []ovrs.Step {
	if len(src) == 0 {
		return nil
	}
	out := make([]ovrs.Step, len(src))
	for i, step := range src {
		out[i] = step
		out[i].Params = copyMap(step.Params)
		if len(step.DependsOn) > 0 {
			deps := make([]string, len(step.DependsOn))
			copy(deps, step.DependsOn)
			out[i].DependsOn = deps
		}
		if step.RetryPolicy != nil {
			policy := *step.RetryPolicy
			out[i].RetryPolicy = &policy
		}
	}
	return out
}

func copyMap(src map[string]any) map[string]any {
	if src == nil {
		return nil
	}
	out := make(map[string]any, len(src))
	for k, v := range src {
		out[k] = deepCopyValue(v)
	}
	return out
}

func deepCopyValue(v any) any {
	switch val := v.(type) {
	case map[string]any:
		return copyMap(val)
	case []any:
		out := make([]any, len(val))
		for i, item := range val {
			out[i] = deepCopyValue(item)
		}
		return out
	default:
		return val
	}
}

func recursivelySubstitute(value any, ctx RenderContext) (any, []error) {
	switch v := value.(type) {
	case string:
		res, err := substitutePlaceholdersInString(v, ctx)
		if err != nil {
			return res, []error{err}
		}
		return res, nil
	case map[string]any:
		var errs []error
		for key, item := range v {
			resolved, itemErrs := recursivelySubstitute(item, ctx)
			if len(itemErrs) > 0 {
				errs = append(errs, itemErrs...)
			}
			v[key] = resolved
		}
		return v, errs
	case []any:
		var errs []error
		for i, item := range v {
			resolved, itemErrs := recursivelySubstitute(item, ctx)
			if len(itemErrs) > 0 {
				errs = append(errs, itemErrs...)
			}
			v[i] = resolved
		}
		return v, errs
	default:
		return value, nil
	}
}

func substitutePlaceholdersInString(input string, ctx RenderContext) (string, error) {
	matches := placeholderPattern.FindAllStringSubmatchIndex(input, -1)
	if len(matches) == 0 {
		return input, nil
	}

	var (
		sb          strings.Builder
		lastIndex   = 0
		firstErr    error
		placeholder string
	)

	for _, match := range matches {
		start := match[0]
		end := match[1]
		contentStart := match[2]
		contentEnd := match[3]

		sb.WriteString(input[lastIndex:start])
		placeholder = strings.TrimSpace(input[contentStart:contentEnd])

		value, err := resolvePlaceholder(placeholder, ctx)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			sb.WriteString(input[start:end])
		} else {
			sb.WriteString(value)
		}
		lastIndex = end
	}

	sb.WriteString(input[lastIndex:])
	return sb.String(), firstErr
}

func resolvePlaceholder(placeholder string, ctx RenderContext) (string, error) {
	if strings.HasPrefix(placeholder, "inventory.") {
		field := strings.TrimPrefix(placeholder, "inventory.")
		value, ok := inventoryFieldValue(field, ctx.Host)
		if !ok {
			return "", fmt.Errorf("unknown inventory field %q", field)
		}
		return value, nil
	}

	if ctx.Parameters != nil {
		if val, ok := ctx.Parameters[placeholder]; ok {
			return fmt.Sprint(val), nil
		}
	}

	return "", fmt.Errorf("unknown parameter %q", placeholder)
}

func inventoryFieldValue(field string, host inventory.Host) (string, bool) {
	switch strings.ToLower(field) {
	case "id", "hostname":
		return host.ID, host.ID != ""
	case "osfamily":
		return host.OSFamily, host.OSFamily != ""
	case "distribution":
		return host.Distribution, host.Distribution != ""
	case "release":
		return host.Release, host.Release != ""
	case "architecture", "arch":
		return host.Architecture, host.Architecture != ""
	default:
		return "", false
	}
}
