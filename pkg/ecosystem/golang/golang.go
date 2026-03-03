// Package golang provides the Go ecosystem plugin.
package golang

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/emphereio/ovrse/pkg/ecosystem"
	"github.com/emphereio/ovrse/pkg/logging"
	"golang.org/x/mod/modfile"
)

func init() {
	_ = ecosystem.Register(&Plugin{})
}

type Plugin struct{}

func (p *Plugin) Info() ecosystem.PluginInfo {
	return ecosystem.PluginInfo{
		Name:        "go",
		DisplayName: "Go Modules",
		Description: "Scans go.mod for Go module vulnerabilities",
		FilePatterns: []string{
			"go.mod",
			"go.sum",
		},
		Priority: 100,
	}
}

func (p *Plugin) Detect(ctx context.Context, path string) bool {
	goMod := filepath.Join(path, "go.mod")
	if _, err := os.Stat(goMod); err == nil {
		return true
	}
	goSum := filepath.Join(path, "go.sum")
	if _, err := os.Stat(goSum); err == nil {
		return true
	}
	return false
}

func (p *Plugin) Scan(ctx context.Context, path string) (*ecosystem.ScanResult, error) {
	logger := logging.WithComponent("ecosystem.go")
	logger.Debug().Str("path", path).Msg("scanning go project")

	goMod := filepath.Join(path, "go.mod")
	packages, err := parseGoMod(goMod)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			logger.Error().Err(err).Msg("failed to parse go.mod")
			return nil, fmt.Errorf("failed to parse go.mod: %w", err)
		}
		goSum := filepath.Join(path, "go.sum")
		packages, err = parseGoSum(goSum)
		if err != nil {
			logger.Error().Err(err).Msg("failed to parse go.sum")
			return nil, fmt.Errorf("no go.mod found and failed to parse go.sum: %w", err)
		}
		logger.Debug().Str("source", "go.sum").Int("packages", len(packages)).Msg("parsed dependencies")
	} else {
		logger.Debug().Str("source", "go.mod").Int("packages", len(packages)).Msg("parsed dependencies")
	}

	findings, err := ecosystem.DefaultOSVClient.CheckPackages(ctx, packages)
	if err != nil {
		return nil, fmt.Errorf("vulnerability check failed: %w", err)
	}

	return &ecosystem.ScanResult{
		Ecosystem:       "go",
		PackagesScanned: len(packages),
		Findings:        findings,
		Status:          ecosystem.ScanStatusSuccess,
	}, nil
}

func (p *Plugin) GetFix(ctx context.Context, pkg ecosystem.Package, vuln ecosystem.Vulnerability) (*ecosystem.FixAction, error) {
	if vuln.FixVersion == "" {
		return &ecosystem.FixAction{
			Type:        "workaround",
			Description: fmt.Sprintf("No fix available for %s. Consider removing or replacing the module.", vuln.ID),
		}, nil
	}

	return &ecosystem.FixAction{
		Type:          "upgrade",
		Command:       fmt.Sprintf("go get %s@%s", pkg.Name, vuln.FixVersion),
		Description:   fmt.Sprintf("Upgrade %s from %s to %s", pkg.Name, pkg.Version, vuln.FixVersion),
		TargetVersion: vuln.FixVersion,
	}, nil
}

func (p *Plugin) NativeAudit(ctx context.Context, path string) (*ecosystem.ScanResult, error) {
	if _, err := exec.LookPath("govulncheck"); err != nil {
		return nil, fmt.Errorf("govulncheck not installed (go install golang.org/x/vuln/cmd/govulncheck@latest)")
	}

	result, err := runGovulncheck(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("govulncheck: %w", err)
	}

	findings := result.toEcosystemFindings()

	return &ecosystem.ScanResult{
		Ecosystem:       "go",
		PackagesScanned: result.ScannedModules,
		Findings:        findings,
		Status:          ecosystem.ScanStatusSuccess,
	}, nil
}

var goSumLineRegex = regexp.MustCompile(`^([^\s]+)\s+(v[^\s/]+)(?:/go\.mod)?\s+`)

func parseGoSum(path string) ([]ecosystem.Package, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer func() { _ = file.Close() }()

	var packages []ecosystem.Package
	seen := make(map[string]bool)

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		matches := goSumLineRegex.FindStringSubmatch(line)
		if matches == nil {
			continue
		}

		name := matches[1]
		version := matches[2]

		version = strings.TrimSuffix(version, "+incompatible")

		pkgKey := name + "@" + version
		if seen[pkgKey] {
			continue
		}
		seen[pkgKey] = true

		packages = append(packages, ecosystem.Package{
			Name:      name,
			Version:   version,
			Ecosystem: "Go",
			Source:    path,
		})
	}

	return packages, scanner.Err()
}

func parseGoMod(path string) ([]ecosystem.Package, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	f, err := modfile.Parse(path, data, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to parse go.mod: %w", err)
	}

	// Collect replace directives; skip local path replacements (no version).
	type replaceKey struct {
		Path    string
		Version string
	}
	replaces := make(map[replaceKey]*modfile.Replace)
	for _, r := range f.Replace {
		if r.New.Version != "" {
			replaces[replaceKey{Path: r.Old.Path, Version: r.Old.Version}] = r
		}
	}

	var packages []ecosystem.Package
	for _, req := range f.Require {
		name := req.Mod.Path
		version := req.Mod.Version

		if r, ok := replaces[replaceKey{Path: name, Version: version}]; ok {
			name = r.New.Path
			version = r.New.Version
		} else if r, ok := replaces[replaceKey{Path: name, Version: ""}]; ok {
			name = r.New.Path
			version = r.New.Version
		}

		packages = append(packages, ecosystem.Package{
			Name:      name,
			Version:   version,
			Ecosystem: "Go",
			Source:    path,
			Direct:   !req.Indirect,
		})
	}

	return packages, nil
}
