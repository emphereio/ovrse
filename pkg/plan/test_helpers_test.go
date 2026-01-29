package plan_test

import "path/filepath"

func repoPath(parts ...string) string {
	prefix := []string{"..", ".."}
	prefix = append(prefix, parts...)
	return filepath.Join(prefix...)
}
