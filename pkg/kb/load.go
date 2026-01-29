package kb

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// LoadCveMappingsFromDir loads all CVE mappings from YAML files under a directory.
func LoadCveMappingsFromDir(root string) ([]*CveMapping, error) {
	var mappings []*CveMapping
	var loadErrors []string

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() || !isYAMLFile(path) {
			return nil
		}

		data, err := os.ReadFile(path)
		if err != nil {
			loadErrors = append(loadErrors, fmt.Sprintf("read %s: %v", path, err))
			return nil
		}

		meta := map[string]any{}
		if err := yaml.Unmarshal(data, &meta); err != nil {
			loadErrors = append(loadErrors, fmt.Sprintf("parse %s: %v", path, err))
			return nil
		}

		if !looksLikeCveMapping(meta) {
			return nil
		}

		var mapping CveMapping
		if err := yaml.Unmarshal(data, &mapping); err != nil {
			loadErrors = append(loadErrors, fmt.Sprintf("decode mapping %s: %v", path, err))
			return nil
		}
		mapping.SourcePath = path
		mappings = append(mappings, &mapping)
		return nil
	})
	if err != nil {
		return nil, err
	}

	if len(loadErrors) > 0 {
		return nil, fmt.Errorf("cve mapping load errors:\n%s", strings.Join(loadErrors, "\n"))
	}
	return mappings, nil
}

// LoadPackageReleasesFromDir loads all package releases from YAML files under a directory.
func LoadPackageReleasesFromDir(root string) ([]*PackageRelease, error) {
	var releases []*PackageRelease
	var loadErrors []string

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() || !isYAMLFile(path) {
			return nil
		}

		data, err := os.ReadFile(path)
		if err != nil {
			loadErrors = append(loadErrors, fmt.Sprintf("read %s: %v", path, err))
			return nil
		}

		meta := map[string]any{}
		if err := yaml.Unmarshal(data, &meta); err != nil {
			loadErrors = append(loadErrors, fmt.Sprintf("parse %s: %v", path, err))
			return nil
		}

		if !looksLikePackageRelease(meta) {
			return nil
		}

		var release PackageRelease
		if err := yaml.Unmarshal(data, &release); err != nil {
			loadErrors = append(loadErrors, fmt.Sprintf("decode package release %s: %v", path, err))
			return nil
		}
		release.SourcePath = path
		releases = append(releases, &release)
		return nil
	})
	if err != nil {
		return nil, err
	}

	if len(loadErrors) > 0 {
		return nil, fmt.Errorf("package release load errors:\n%s", strings.Join(loadErrors, "\n"))
	}
	return releases, nil
}

func looksLikeCveMapping(meta map[string]any) bool {
	if meta == nil {
		return false
	}
	if _, ok := meta["cveId"]; ok {
		return true
	}
	if _, ok := meta["templateId"]; ok {
		return true
	}
	return false
}

func looksLikePackageRelease(meta map[string]any) bool {
	if meta == nil {
		return false
	}
	if _, ok := meta["packageName"]; ok {
		return true
	}
	if _, ok := meta["fixesCves"]; ok {
		return true
	}
	return false
}

func isYAMLFile(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	return ext == ".yaml" || ext == ".yml"
}
