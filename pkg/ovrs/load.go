package ovrs

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// LoadTemplateFromFile loads a single template from a YAML file.
func LoadTemplateFromFile(path string) (*Template, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read template %s: %w", path, err)
	}

	var tmpl Template
	if err := yaml.Unmarshal(data, &tmpl); err != nil {
		return nil, fmt.Errorf("parse template %s: %w", path, err)
	}
	tmpl.SourcePath = path

	return &tmpl, nil
}

// LoadTemplatesFromDir recursively loads all .yaml and .yml files under a directory.
func LoadTemplatesFromDir(root string) ([]*Template, error) {
	var templates []*Template
	var loadErrors []string

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}

		if d.IsDir() {
			return nil
		}

		if !isYAMLFile(path) {
			return nil
		}

		tmpl, err := LoadTemplateFromFile(path)
		if err != nil {
			loadErrors = append(loadErrors, err.Error())
			return nil
		}

		templates = append(templates, tmpl)
		return nil
	})
	if err != nil {
		return nil, err
	}

	if len(loadErrors) > 0 {
		return nil, fmt.Errorf("template load errors:\n%s", strings.Join(loadErrors, "\n"))
	}

	return templates, nil
}

func isYAMLFile(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	return ext == ".yaml" || ext == ".yml"
}
