package ovrs_test

import (
	"path/filepath"
	"testing"

	"github.com/emphereio/ovrse/pkg/ovrs"
)

func TestLoadAndValidateTemplate(t *testing.T) {
	templateDir := repoPath("examples", "templates")
	templates, err := ovrs.LoadTemplatesFromDir(templateDir)
	if err != nil {
		t.Fatalf("LoadTemplatesFromDir failed: %v", err)
	}
	if len(templates) == 0 {
		t.Fatalf("expected at least one template in %s", templateDir)
	}

	for _, tmpl := range templates {
		if errs := tmpl.Validate(); len(errs) > 0 {
			t.Fatalf("template %s (%s) failed validation: %v", tmpl.ID, tmpl.SourcePath, errs)
		}
	}
}

func repoPath(parts ...string) string {
	prefix := []string{"..", ".."}
	prefix = append(prefix, parts...)
	return filepath.Join(prefix...)
}
