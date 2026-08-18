package ecosystem

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestConvertOSVVuln(t *testing.T) {
	tests := []struct {
		name     string
		vuln     osvVulnerability
		wantID   string
		wantFix  string
		wantAny  bool // just check it doesn't panic
	}{
		{
			name: "basic vulnerability",
			vuln: osvVulnerability{
				ID:      "GHSA-1234-5678",
				Summary: "Test vulnerability",
				Details: "Detailed description",
				Aliases: []string{"CVE-2021-12345"},
				Affected: []osvAffected{
					{
						Ranges: []osvRange{
							{
								Events: []osvEvent{
									{Introduced: "1.0.0"},
									{Fixed: "2.0.0"},
								},
							},
						},
					},
				},
			},
			wantID:  "GHSA-1234-5678",
			wantFix: "2.0.0",
		},
		{
			name: "no fix version",
			vuln: osvVulnerability{
				ID:      "GHSA-no-fix",
				Summary: "No fix available",
			},
			wantID:  "GHSA-no-fix",
			wantFix: "",
		},
		{
			name: "multiple aliases",
			vuln: osvVulnerability{
				ID:      "GHSA-xxxx",
				Aliases: []string{"CVE-2021-11111", "CVE-2021-22222", "GHSA-other"},
			},
			wantID:  "GHSA-xxxx",
			wantAny: true,
		},
		{
			name: "with database specific severity",
			vuln: osvVulnerability{
				ID: "GHSA-sev",
				DatabaseSpecific: map[string]interface{}{
					"severity":   "HIGH",
					"cvss_score": 7.5,
				},
			},
			wantID:  "GHSA-sev",
			wantAny: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vuln := convertOSVVuln(tt.vuln, Package{Name: "example", Version: "1.0.0", Ecosystem: "npm"})
			if vuln.ID != tt.wantID {
				t.Errorf("ID = %q, want %q", vuln.ID, tt.wantID)
			}
			if !tt.wantAny && vuln.FixVersion != tt.wantFix {
				t.Errorf("FixVersion = %q, want %q", vuln.FixVersion, tt.wantFix)
			}
		})
	}
}

func TestExtractSeverity(t *testing.T) {
	tests := []struct {
		name         string
		vuln         osvVulnerability
		wantSeverity string
		wantScore    bool
	}{
		{
			name: "from database specific string",
			vuln: osvVulnerability{
				DatabaseSpecific: map[string]interface{}{
					"severity": "HIGH",
				},
			},
			wantSeverity: "HIGH",
			wantScore:    false,
		},
		{
			name: "from database specific score",
			vuln: osvVulnerability{
				DatabaseSpecific: map[string]interface{}{
					"cvss_score": 9.5,
				},
			},
			wantSeverity: "CRITICAL",
			wantScore:    true,
		},
		{
			name:         "no severity info",
			vuln:         osvVulnerability{},
			wantSeverity: "UNKNOWN",
			wantScore:    false,
		},
		{
			name: "lowercase severity",
			vuln: osvVulnerability{
				DatabaseSpecific: map[string]interface{}{
					"severity": "medium",
				},
			},
			wantSeverity: "MEDIUM",
			wantScore:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			severity, score := extractSeverity(tt.vuln)
			if severity != tt.wantSeverity {
				t.Errorf("severity = %q, want %q", severity, tt.wantSeverity)
			}
			hasScore := score != nil
			if hasScore != tt.wantScore {
				t.Errorf("hasScore = %v, want %v", hasScore, tt.wantScore)
			}
		})
	}
}

func TestCVSSToSeverity(t *testing.T) {
	tests := []struct {
		score float64
		want  string
	}{
		{10.0, "CRITICAL"},
		{9.0, "CRITICAL"},
		{8.5, "HIGH"},
		{7.0, "HIGH"},
		{6.9, "MEDIUM"},
		{4.0, "MEDIUM"},
		{3.9, "LOW"},
		{0.1, "LOW"},
		{0.0, "UNKNOWN"},
		{-1.0, "UNKNOWN"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := cvssToSeverity(tt.score)
			if got != tt.want {
				t.Errorf("cvssToSeverity(%v) = %q, want %q", tt.score, got, tt.want)
			}
		})
	}
}

func TestExtractFixVersion(t *testing.T) {
	tests := []struct {
		name    string
		vuln    osvVulnerability
		pkg     Package
		wantFix string
	}{
		{
			name: "single range with fix",
			vuln: osvVulnerability{
				Affected: []osvAffected{
					{
						Ranges: []osvRange{
							{
								Events: []osvEvent{
									{Introduced: "1.0.0"},
									{Fixed: "1.0.1"},
								},
							},
						},
					},
				},
			},
			wantFix: "1.0.1",
		},
		{
			name: "multiple ranges, first fix wins",
			vuln: osvVulnerability{
				Affected: []osvAffected{
					{
						Ranges: []osvRange{
							{
								Events: []osvEvent{
									{Fixed: "2.0.0"},
								},
							},
							{
								Events: []osvEvent{
									{Fixed: "3.0.0"},
								},
							},
						},
					},
				},
			},
			wantFix: "2.0.0",
		},
		{
			name: "no fix - last affected only",
			vuln: osvVulnerability{
				Affected: []osvAffected{
					{
						Ranges: []osvRange{
							{
								Events: []osvEvent{
									{Introduced: "1.0.0"},
									{LastAffected: "1.5.0"},
								},
							},
						},
					},
				},
			},
			wantFix: "",
		},
		{
			name:    "empty affected",
			vuln:    osvVulnerability{},
			wantFix: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fix := extractFixVersion(tt.vuln, tt.pkg)
			if fix != tt.wantFix {
				t.Errorf("extractFixVersion() = %q, want %q", fix, tt.wantFix)
			}
		})
	}
}

// multiBranchVuln mirrors the shape of a real advisory that patches several
// maintained branches in one unordered event list (PYSEC-2023-100 / Django).
func multiBranchVuln() osvVulnerability {
	return osvVulnerability{
		ID: "PYSEC-multi-branch",
		Affected: []osvAffected{
			{
				Package: osvPackage{Name: "django", Ecosystem: "PyPI"},
				Ranges: []osvRange{
					{
						Type: "ECOSYSTEM",
						Events: []osvEvent{
							{Introduced: "4.2"},
							{Fixed: "4.2.3"},
							{Introduced: "4.0"},
							{Fixed: "4.1.10"},
							{Introduced: "3.2"},
							{Fixed: "3.2.20"},
						},
					},
				},
			},
		},
	}
}

func TestExtractFixVersionSelectsInstalledBranch(t *testing.T) {
	tests := []struct {
		name    string
		version string
		wantFix string
	}{
		{"oldest supported branch", "3.2.10", "3.2.20"},
		{"middle branch", "4.0.5", "4.1.10"},
		{"newest branch", "4.2.1", "4.2.3"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pkg := Package{Name: "django", Version: tt.version, Ecosystem: "PyPI"}
			if fix := extractFixVersion(multiBranchVuln(), pkg); fix != tt.wantFix {
				t.Errorf("extractFixVersion() for %s = %q, want %q", tt.version, fix, tt.wantFix)
			}
		})
	}
}

// perBranchVuln mirrors an advisory that gives each maintained branch its own
// affected entry, as GitHub advisories for Django do (GHSA-2gwj-7jmv-h26r).
func perBranchVuln() osvVulnerability {
	branch := func(introduced, fixed string) osvAffected {
		return osvAffected{
			Package: osvPackage{Name: "django", Ecosystem: "PyPI"},
			Ranges: []osvRange{
				{
					Type: "ECOSYSTEM",
					Events: []osvEvent{
						{Introduced: introduced},
						{Fixed: fixed},
					},
				},
			},
		}
	}

	return osvVulnerability{
		ID: "GHSA-per-branch",
		Affected: []osvAffected{
			branch("2.2", "2.2.28"),
			branch("3.2", "3.2.13"),
			branch("4.0", "4.0.4"),
		},
	}
}

func TestExtractFixVersionSearchesEveryAffectedEntry(t *testing.T) {
	// The 2.2 entry comes first and offers a fix, but 3.2.10 belongs to the
	// 3.2 branch: falling back to the first entry's fix would be a downgrade.
	pkg := Package{Name: "django", Version: "3.2.10", Ecosystem: "PyPI"}
	if fix := extractFixVersion(perBranchVuln(), pkg); fix != "3.2.13" {
		t.Errorf("extractFixVersion() = %q, want %q", fix, "3.2.13")
	}

	pkg.Version = "4.0.1"
	if fix := extractFixVersion(perBranchVuln(), pkg); fix != "4.0.4" {
		t.Errorf("extractFixVersion() = %q, want %q", fix, "4.0.4")
	}

	// A version no branch covers still reports a fix, as before.
	pkg.Version = "1.11.29"
	if fix := extractFixVersion(perBranchVuln(), pkg); fix != "2.2.28" {
		t.Errorf("extractFixVersion() = %q, want %q", fix, "2.2.28")
	}
}

func TestExtractFixVersionFallsBackWithoutVersion(t *testing.T) {
	// No installed version to compare against: keep the previous behaviour of
	// returning the first fix event rather than reporting no fix at all.
	pkg := Package{Name: "django", Ecosystem: "PyPI"}
	if fix := extractFixVersion(multiBranchVuln(), pkg); fix != "4.2.3" {
		t.Errorf("extractFixVersion() = %q, want %q", fix, "4.2.3")
	}

	// An installed version the format cannot compare falls back the same way.
	pkg.Version = "not-a-version"
	if fix := extractFixVersion(multiBranchVuln(), pkg); fix != "4.2.3" {
		t.Errorf("extractFixVersion() with uncomparable version = %q, want %q", fix, "4.2.3")
	}
}

func TestExtractFixVersionIgnoresOtherPackages(t *testing.T) {
	vuln := osvVulnerability{
		ID: "GHSA-two-packages",
		Affected: []osvAffected{
			{
				Package: osvPackage{Name: "scanned-pkg", Ecosystem: "npm"},
				Ranges: []osvRange{
					{
						Type: "SEMVER",
						Events: []osvEvent{
							{Introduced: "0"},
							{LastAffected: "1.4.0"},
						},
					},
				},
			},
			{
				Package: osvPackage{Name: "other-pkg", Ecosystem: "npm"},
				Ranges: []osvRange{
					{
						Type: "SEMVER",
						Events: []osvEvent{
							{Introduced: "0"},
							{Fixed: "9.9.9"},
						},
					},
				},
			},
		},
	}

	pkg := Package{Name: "scanned-pkg", Version: "1.2.0", Ecosystem: "npm"}
	if fix := extractFixVersion(vuln, pkg); fix != "" {
		t.Errorf("extractFixVersion() = %q, want %q (9.9.9 fixes a different package)", fix, "")
	}

	// An advisory that omits package metadata still resolves through the
	// fallback scan over every affected entry.
	vuln.Affected[0].Package = osvPackage{}
	vuln.Affected[1].Package = osvPackage{}
	if fix := extractFixVersion(vuln, pkg); fix != "9.9.9" {
		t.Errorf("extractFixVersion() with unnamed packages = %q, want %q", fix, "9.9.9")
	}
}

func TestExtractFixVersionPrefersVersionsOverCommits(t *testing.T) {
	// Advisories often carry a GIT range whose "fixed" event is a commit hash
	// alongside the ecosystem range (PYSEC-2022-304 / Django).
	commit := "5b6b257fa7ec37ff27965358800c67e2dd11c924"
	vuln := osvVulnerability{
		ID: "PYSEC-git-range",
		Affected: []osvAffected{
			{
				Package: osvPackage{Name: "django", Ecosystem: "PyPI"},
				Ranges: []osvRange{
					{
						Type: "GIT",
						Events: []osvEvent{
							{Introduced: "0"},
							{Fixed: commit},
						},
					},
					{
						Type: "ECOSYSTEM",
						Events: []osvEvent{
							{Introduced: "3.2"},
							{Fixed: "3.2.16"},
							{Introduced: "4.1"},
							{Fixed: "4.1.2"},
						},
					},
				},
			},
		},
	}

	pkg := Package{Name: "django", Version: "4.1.1", Ecosystem: "PyPI"}
	if fix := extractFixVersion(vuln, pkg); fix != "4.1.2" {
		t.Errorf("extractFixVersion() = %q, want %q", fix, "4.1.2")
	}

	// Without an installed version the ecosystem range is still preferred to
	// the commit hash.
	pkg.Version = ""
	if fix := extractFixVersion(vuln, pkg); fix != "3.2.16" {
		t.Errorf("extractFixVersion() without version = %q, want %q", fix, "3.2.16")
	}

	// A GIT-only advisory has nothing else to offer, so the hash is still
	// returned as before.
	vuln.Affected[0].Ranges = vuln.Affected[0].Ranges[:1]
	if fix := extractFixVersion(vuln, pkg); fix != commit {
		t.Errorf("extractFixVersion() for GIT-only advisory = %q, want %q", fix, commit)
	}
}

func TestCheckPackagesReportsBranchFixVersion(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := osvBatchResponse{
			Results: []osvQueryResult{
				{Vulns: []osvVulnerability{multiBranchVuln()}},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := newOSVClientWithURL(server.URL)
	findings, err := client.CheckPackages(context.Background(), []Package{
		{Name: "django", Version: "3.2.10", Ecosystem: "PyPI"},
	})
	if err != nil {
		t.Fatalf("CheckPackages failed: %v", err)
	}

	if len(findings) != 1 || len(findings[0].Vulnerabilities) != 1 {
		t.Fatalf("expected 1 finding with 1 vulnerability, got %+v", findings)
	}

	if got := findings[0].Vulnerabilities[0].FixVersion; got != "3.2.20" {
		t.Errorf("FixVersion = %q, want %q (upgrading 3.2.10 to 4.2.3 changes major version)", got, "3.2.20")
	}
}

// osvServer serves the two endpoints a scan uses: a batch query that answers
// with IDs only, exactly as OSV does, and the per-vulnerability record.
func osvServer(t *testing.T, ids [][]string, details map[string]osvVulnerability, detailStatus int) (*httptest.Server, *int32) {
	t.Helper()

	var detailRequests int32

	mux := http.NewServeMux()
	mux.HandleFunc("/querybatch", func(w http.ResponseWriter, r *http.Request) {
		resp := osvBatchResponse{}
		for _, perPackage := range ids {
			result := osvQueryResult{}
			for _, id := range perPackage {
				result.Vulns = append(result.Vulns, osvVulnerability{ID: id})
			}
			resp.Results = append(resp.Results, result)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	})
	mux.HandleFunc("/vulns/", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&detailRequests, 1)
		if detailStatus != http.StatusOK {
			w.WriteHeader(detailStatus)
			return
		}
		id := strings.TrimPrefix(r.URL.Path, "/vulns/")
		detail, ok := details[id]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(detail)
	})

	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	return server, &detailRequests
}

func TestCheckPackagesFillsInBatchResults(t *testing.T) {
	detail := multiBranchVuln()
	server, requests := osvServer(t,
		[][]string{{detail.ID}},
		map[string]osvVulnerability{detail.ID: detail},
		http.StatusOK,
	)

	client := newOSVClientWithURL(server.URL)
	findings, err := client.CheckPackages(context.Background(), []Package{
		{Name: "django", Version: "3.2.10", Ecosystem: "PyPI"},
	})
	if err != nil {
		t.Fatalf("CheckPackages failed: %v", err)
	}

	if len(findings) != 1 || len(findings[0].Vulnerabilities) != 1 {
		t.Fatalf("expected 1 finding with 1 vulnerability, got %+v", findings)
	}

	// The batch endpoint returns IDs only, so without the follow-up lookup
	// there is no fix version to report at all.
	if got := findings[0].Vulnerabilities[0].FixVersion; got != "3.2.20" {
		t.Errorf("FixVersion = %q, want %q", got, "3.2.20")
	}
	if got := atomic.LoadInt32(requests); got != 1 {
		t.Errorf("advisory lookups = %d, want 1", got)
	}
}

func TestCheckPackagesFetchesEachAdvisoryOnce(t *testing.T) {
	detail := multiBranchVuln()
	server, requests := osvServer(t,
		[][]string{{detail.ID}, {detail.ID}},
		map[string]osvVulnerability{detail.ID: detail},
		http.StatusOK,
	)

	client := newOSVClientWithURL(server.URL)
	packages := []Package{
		{Name: "django", Version: "3.2.10", Ecosystem: "PyPI"},
		{Name: "django", Version: "4.0.5", Ecosystem: "PyPI"},
	}

	findings, err := client.CheckPackages(context.Background(), packages)
	if err != nil {
		t.Fatalf("CheckPackages failed: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}

	// The same advisory shared by both packages costs one lookup, and each
	// package still gets the fix version for its own branch.
	if got := atomic.LoadInt32(requests); got != 1 {
		t.Errorf("advisory lookups = %d, want 1", got)
	}
	if got := findings[0].Vulnerabilities[0].FixVersion; got != "3.2.20" {
		t.Errorf("FixVersion for 3.2.10 = %q, want %q", got, "3.2.20")
	}
	if got := findings[1].Vulnerabilities[0].FixVersion; got != "4.1.10" {
		t.Errorf("FixVersion for 4.0.5 = %q, want %q", got, "4.1.10")
	}

	// A second scan reuses the cached advisory rather than fetching it again.
	if _, err := client.CheckPackages(context.Background(), packages); err != nil {
		t.Fatalf("second CheckPackages failed: %v", err)
	}
	if got := atomic.LoadInt32(requests); got != 1 {
		t.Errorf("advisory lookups after second scan = %d, want 1", got)
	}
}

func TestCheckPackagesSurvivesAdvisoryLookupFailure(t *testing.T) {
	server, requests := osvServer(t,
		[][]string{{"GHSA-unreachable"}},
		nil,
		http.StatusInternalServerError,
	)

	client := newOSVClientWithURL(server.URL)
	findings, err := client.CheckPackages(context.Background(), []Package{
		{Name: "django", Version: "3.2.10", Ecosystem: "PyPI"},
	})
	if err != nil {
		t.Fatalf("CheckPackages failed: %v", err)
	}

	// The finding is still reported, just without the enrichment.
	if len(findings) != 1 || len(findings[0].Vulnerabilities) != 1 {
		t.Fatalf("expected 1 finding with 1 vulnerability, got %+v", findings)
	}
	if got := findings[0].Vulnerabilities[0].ID; got != "GHSA-unreachable" {
		t.Errorf("vulnerability ID = %q, want %q", got, "GHSA-unreachable")
	}
	if got := findings[0].Vulnerabilities[0].FixVersion; got != "" {
		t.Errorf("FixVersion = %q, want %q", got, "")
	}
	// A 500 is transient, so the lookup is retried before it is given up on.
	if got := atomic.LoadInt32(requests); got != osvMaxRetries {
		t.Errorf("advisory lookups = %d, want %d", got, osvMaxRetries)
	}
}

func TestMatchesPackage(t *testing.T) {
	tests := []struct {
		name    string
		osvPkg  osvPackage
		pkg     Package
		want    bool
	}{
		{
			name:   "exact match",
			osvPkg: osvPackage{Name: "lodash", Ecosystem: "npm"},
			pkg:    Package{Name: "lodash", Ecosystem: "npm"},
			want:   true,
		},
		{
			name:   "case insensitive name",
			osvPkg: osvPackage{Name: "Lodash", Ecosystem: "npm"},
			pkg:    Package{Name: "lodash", Ecosystem: "npm"},
			want:   true,
		},
		{
			name:   "case insensitive ecosystem",
			osvPkg: osvPackage{Name: "flask", Ecosystem: "PyPI"},
			pkg:    Package{Name: "flask", Ecosystem: "pypi"},
			want:   true,
		},
		{
			name:   "pypi alias pip",
			osvPkg: osvPackage{Name: "requests", Ecosystem: "PyPI"},
			pkg:    Package{Name: "requests", Ecosystem: "pip"},
			want:   true,
		},
		{
			name:   "pypi alias python",
			osvPkg: osvPackage{Name: "requests", Ecosystem: "PyPI"},
			pkg:    Package{Name: "requests", Ecosystem: "python"},
			want:   true,
		},
		{
			name:   "npm alias node",
			osvPkg: osvPackage{Name: "express", Ecosystem: "npm"},
			pkg:    Package{Name: "express", Ecosystem: "node"},
			want:   true,
		},
		{
			name:   "go alias golang",
			osvPkg: osvPackage{Name: "github.com/pkg/errors", Ecosystem: "Go"},
			pkg:    Package{Name: "github.com/pkg/errors", Ecosystem: "golang"},
			want:   true,
		},
		{
			name:   "different name",
			osvPkg: osvPackage{Name: "lodash", Ecosystem: "npm"},
			pkg:    Package{Name: "underscore", Ecosystem: "npm"},
			want:   false,
		},
		{
			name:   "different ecosystem",
			osvPkg: osvPackage{Name: "requests", Ecosystem: "npm"},
			pkg:    Package{Name: "requests", Ecosystem: "pypi"},
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := matchesPackage(tt.osvPkg, tt.pkg)
			if got != tt.want {
				t.Errorf("matchesPackage() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCheckPackagesEmpty(t *testing.T) {
	client := NewOSVClient()
	findings, err := client.CheckPackages(context.Background(), []Package{})
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if findings != nil {
		t.Errorf("expected nil findings, got %v", findings)
	}
}

func TestNewOSVClient(t *testing.T) {
	client := NewOSVClient()
	if client == nil {
		t.Fatal("NewOSVClient returned nil")
	}
	if client.httpClient == nil {
		t.Error("httpClient is nil")
	}
}

func TestDefaultOSVClient(t *testing.T) {
	if DefaultOSVClient == nil {
		t.Fatal("DefaultOSVClient is nil")
	}
}

func TestAffectedResultStruct(t *testing.T) {
	result := AffectedResult{
		Status:     1,
		Message:    "test message",
		VulnID:     "CVE-2021-12345",
		FixVersion: "2.0.0",
		Severity:   "HIGH",
	}

	if result.VulnID != "CVE-2021-12345" {
		t.Errorf("unexpected VulnID: %s", result.VulnID)
	}
	if result.FixVersion != "2.0.0" {
		t.Errorf("unexpected FixVersion: %s", result.FixVersion)
	}
}

func TestResolveCVEID(t *testing.T) {
	ctx := context.Background()

	t.Run("CVE passes through unchanged", func(t *testing.T) {
		client := NewOSVClient()
		result, err := client.ResolveCVEID(ctx, "CVE-2021-44228")
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if result != "CVE-2021-44228" {
			t.Errorf("expected CVE-2021-44228, got %s", result)
		}
	})

	t.Run("empty string short-circuits without network", func(t *testing.T) {
		client := NewOSVClient()
		// This should NOT hit the network - just return empty immediately
		result, err := client.ResolveCVEID(ctx, "")
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if result != "" {
			t.Errorf("expected empty string, got %s", result)
		}
	})

	t.Run("whitespace-only string short-circuits without network", func(t *testing.T) {
		client := NewOSVClient()
		result, err := client.ResolveCVEID(ctx, "   ")
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if result != "" {
			t.Errorf("expected empty string, got %s", result)
		}
	})
}

// TestResolveCVEIDMocked tests ResolveCVEID with mocked HTTP responses.
func TestResolveCVEIDMocked(t *testing.T) {
	ctx := context.Background()

	t.Run("resolves GHSA to CVE", func(t *testing.T) {
		// Mock OSV server response
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/vulns/GHSA-xxxx-yyyy-zzzz" {
				t.Errorf("unexpected path: %s", r.URL.Path)
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(osvVulnerability{
				ID:      "GHSA-xxxx-yyyy-zzzz",
				Aliases: []string{"CVE-2023-12345"},
			})
		}))
		defer server.Close()

		client := newTestOSVClient(server.URL)
		result, err := client.ResolveCVEID(ctx, "GHSA-xxxx-yyyy-zzzz")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result != "CVE-2023-12345" {
			t.Errorf("expected CVE-2023-12345, got %s", result)
		}
	})

	t.Run("resolves PYSEC to CVE", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(osvVulnerability{
				ID:      "PYSEC-2024-123",
				Aliases: []string{"CVE-2024-9999", "GHSA-aaaa-bbbb-cccc"},
			})
		}))
		defer server.Close()

		client := newTestOSVClient(server.URL)
		result, err := client.ResolveCVEID(ctx, "PYSEC-2024-123")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result != "CVE-2024-9999" {
			t.Errorf("expected CVE-2024-9999, got %s", result)
		}
	})

	t.Run("returns original if no CVE alias", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(osvVulnerability{
				ID:      "GHSA-no-cve",
				Aliases: []string{"PYSEC-2024-001"}, // No CVE alias
			})
		}))
		defer server.Close()

		client := newTestOSVClient(server.URL)
		result, err := client.ResolveCVEID(ctx, "GHSA-no-cve")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result != "GHSA-no-cve" {
			t.Errorf("expected GHSA-no-cve, got %s", result)
		}
	})

	t.Run("returns original on 404", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		}))
		defer server.Close()

		client := newTestOSVClient(server.URL)
		result, err := client.ResolveCVEID(ctx, "UNKNOWN-2024-001")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result != "UNKNOWN-2024-001" {
			t.Errorf("expected UNKNOWN-2024-001, got %s", result)
		}
	})

	t.Run("returns error on server error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer server.Close()

		client := newTestOSVClient(server.URL)
		_, err := client.ResolveCVEID(ctx, "GHSA-error")
		if err == nil {
			t.Error("expected error for 500 response")
		}
	})

	t.Run("returns error on rate limit", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusTooManyRequests)
		}))
		defer server.Close()

		client := newTestOSVClient(server.URL)
		_, err := client.ResolveCVEID(ctx, "GHSA-rate-limited")
		if err == nil {
			t.Error("expected error for 429 response")
		}
	})

	t.Run("returns error on malformed JSON", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte("{invalid json"))
		}))
		defer server.Close()

		client := newTestOSVClient(server.URL)
		_, err := client.ResolveCVEID(ctx, "GHSA-bad-json")
		if err == nil {
			t.Error("expected error for malformed JSON")
		}
	})

	t.Run("first CVE alias wins", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(osvVulnerability{
				ID:      "GHSA-multi",
				Aliases: []string{"CVE-2023-11111", "CVE-2023-22222"},
			})
		}))
		defer server.Close()

		client := newTestOSVClient(server.URL)
		result, err := client.ResolveCVEID(ctx, "GHSA-multi")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		// Should return the first CVE alias
		if result != "CVE-2023-11111" {
			t.Errorf("expected CVE-2023-11111 (first CVE alias), got %s", result)
		}
	})

	t.Run("empty aliases list", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(osvVulnerability{
				ID:      "GHSA-no-aliases",
				Aliases: []string{},
			})
		}))
		defer server.Close()

		client := newTestOSVClient(server.URL)
		result, err := client.ResolveCVEID(ctx, "GHSA-no-aliases")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result != "GHSA-no-aliases" {
			t.Errorf("expected GHSA-no-aliases, got %s", result)
		}
	})
}

// newTestOSVClient creates an OSV client that uses a test server URL.
func newTestOSVClient(baseURL string) *OSVClient {
	return newOSVClientWithURL(baseURL)
}

// testNetError implements net.Error for testing retryable network errors.
type testNetError struct {
	timeout bool
}

func (e *testNetError) Error() string   { return "test net error" }
func (e *testNetError) Timeout() bool   { return e.timeout }
func (e *testNetError) Temporary() bool { return false }

func TestIsRetryableError(t *testing.T) {
	tests := []struct {
		name    string
		err     error
		want    bool
	}{
		{
			name: "too many queries",
			err:  fmt.Errorf("OSV API error (status 400): Too many queries"),
			want: true,
		},
		{
			name: "rate limit 429",
			err:  fmt.Errorf("OSV API error (status 429): rate limited"),
			want: true,
		},
		{
			name: "server error 500",
			err:  fmt.Errorf("OSV API error (status 500): internal error"),
			want: true,
		},
		{
			name: "bad gateway 502",
			err:  fmt.Errorf("OSV API error (status 502): bad gateway"),
			want: true,
		},
		{
			name: "service unavailable 503",
			err:  fmt.Errorf("OSV API error (status 503): unavailable"),
			want: true,
		},
		{
			name: "gateway timeout 504",
			err:  fmt.Errorf("OSV API error (status 504): timeout"),
			want: true,
		},
		{
			name: "bad request 400 without too many queries",
			err:  fmt.Errorf("OSV API error (status 400): invalid request"),
			want: false,
		},
		{
			name: "not found 404",
			err:  fmt.Errorf("OSV API error (status 404): not found"),
			want: false,
		},
		{
			name: "non-network wrapped error",
			err:  fmt.Errorf("failed to send request: connection refused"),
			want: false,
		},
		{
			name: "net.Error timeout",
			err:  &testNetError{timeout: true},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isRetryableError(tt.err)
			if got != tt.want {
				t.Errorf("isRetryableError() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCheckPackagesBatchChunking(t *testing.T) {
	var requestCount int
	var requestSizes []int

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++

		var req osvBatchRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("failed to decode request: %v", err)
		}
		requestSizes = append(requestSizes, len(req.Queries))

		// Return empty results for each query
		results := make([]osvQueryResult, len(req.Queries))
		resp := osvBatchResponse{Results: results}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := newOSVClientWithURL(server.URL)

	// Create 1200 packages (should result in 3 batches: 500, 500, 200)
	packages := make([]Package, 1200)
	for i := range packages {
		packages[i] = Package{
			Name:      fmt.Sprintf("pkg-%d", i),
			Version:   "1.0.0",
			Ecosystem: "npm",
		}
	}

	_, err := client.CheckPackages(context.Background(), packages)
	if err != nil {
		t.Fatalf("CheckPackages failed: %v", err)
	}

	if requestCount != 3 {
		t.Errorf("expected 3 batch requests, got %d", requestCount)
	}

	expectedSizes := []int{500, 500, 200}
	for i, size := range requestSizes {
		if size != expectedSizes[i] {
			t.Errorf("batch %d: expected size %d, got %d", i, expectedSizes[i], size)
		}
	}
}

func TestCheckPackagesRetryOnTransientError(t *testing.T) {
	var attemptCount int

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attemptCount++
		if attemptCount < 3 {
			// Return 400 with "Too many queries" error for first 2 attempts
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"code":3,"message":"Too many queries."}`))
			return
		}
		// Return success on 3rd attempt
		var req osvBatchRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		results := make([]osvQueryResult, len(req.Queries))
		resp := osvBatchResponse{Results: results}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := newOSVClientWithURL(server.URL)

	packages := []Package{
		{Name: "lodash", Version: "4.17.15", Ecosystem: "npm"},
	}

	_, err := client.CheckPackages(context.Background(), packages)
	if err != nil {
		t.Fatalf("CheckPackages failed: %v", err)
	}

	if attemptCount != 3 {
		t.Errorf("expected 3 attempts, got %d", attemptCount)
	}
}

func TestCheckPackagesRetryExhausted(t *testing.T) {
	var attemptCount int

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attemptCount++
		// Always return retryable error
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"internal server error"}`))
	}))
	defer server.Close()

	client := newOSVClientWithURL(server.URL)

	packages := []Package{
		{Name: "lodash", Version: "4.17.15", Ecosystem: "npm"},
	}

	_, err := client.CheckPackages(context.Background(), packages)
	if err == nil {
		t.Fatal("expected error after all retries exhausted")
	}

	if attemptCount != osvMaxRetries {
		t.Errorf("expected %d attempts, got %d", osvMaxRetries, attemptCount)
	}

	if !strings.Contains(err.Error(), fmt.Sprintf("failed after %d attempts", osvMaxRetries)) {
		t.Errorf("expected 'failed after %d attempts' in error, got: %s", osvMaxRetries, err.Error())
	}
}

func TestCheckPackagesWithVulnerabilities(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := osvBatchResponse{
			Results: []osvQueryResult{
				{
					Vulns: []osvVulnerability{
						{
							ID:      "GHSA-1234",
							Summary: "Test vulnerability",
							Aliases: []string{"CVE-2021-12345"},
						},
					},
				},
				{
					Vulns: []osvVulnerability{}, // No vulns for second package
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := newOSVClientWithURL(server.URL)

	packages := []Package{
		{Name: "vulnerable-pkg", Version: "1.0.0", Ecosystem: "npm"},
		{Name: "safe-pkg", Version: "2.0.0", Ecosystem: "npm"},
	}

	findings, err := client.CheckPackages(context.Background(), packages)
	if err != nil {
		t.Fatalf("CheckPackages failed: %v", err)
	}

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	if findings[0].Package.Name != "vulnerable-pkg" {
		t.Errorf("expected finding for vulnerable-pkg, got %s", findings[0].Package.Name)
	}

	if len(findings[0].Vulnerabilities) != 1 {
		t.Errorf("expected 1 vulnerability, got %d", len(findings[0].Vulnerabilities))
	}

	if findings[0].Vulnerabilities[0].ID != "GHSA-1234" {
		t.Errorf("expected GHSA-1234, got %s", findings[0].Vulnerabilities[0].ID)
	}
}
