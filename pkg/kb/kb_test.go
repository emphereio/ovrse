package kb_test

import (
	"path/filepath"
	"testing"

	"github.com/emphereio/ovrse/pkg/kb"
)

func TestLoadAndValidateKnowledgeBase(t *testing.T) {
	kbDir := repoPath("examples", "kb")

	mappings, err := kb.LoadCveMappingsFromDir(kbDir)
	if err != nil {
		t.Fatalf("LoadCveMappingsFromDir failed: %v", err)
	}
	if len(mappings) == 0 {
		t.Fatalf("expected at least one CVE mapping in %s", kbDir)
	}
	for _, mapping := range mappings {
		if errs := mapping.Validate(); len(errs) > 0 {
			t.Fatalf("mapping %s (%s) failed validation: %v", mapping.CVEID, mapping.SourcePath, errs)
		}
	}

	releases, err := kb.LoadPackageReleasesFromDir(kbDir)
	if err != nil {
		t.Fatalf("LoadPackageReleasesFromDir failed: %v", err)
	}
	if len(releases) == 0 {
		t.Fatalf("expected at least one package release in %s", kbDir)
	}
	for _, release := range releases {
		if errs := release.Validate(); len(errs) > 0 {
			t.Fatalf("release %s %s (%s) failed validation: %v", release.PackageName, release.Version, release.SourcePath, errs)
		}
	}
}

func repoPath(parts ...string) string {
	prefix := []string{"..", ".."}
	prefix = append(prefix, parts...)
	return filepath.Join(prefix...)
}
