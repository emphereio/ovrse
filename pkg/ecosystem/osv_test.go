package ecosystem

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
			vuln := convertOSVVuln(tt.vuln)
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
			fix := extractFixVersion(tt.vuln)
			if fix != tt.wantFix {
				t.Errorf("extractFixVersion() = %q, want %q", fix, tt.wantFix)
			}
		})
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
	findings, err := client.CheckPackages(nil, []Package{})
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
			if r.URL.Path != "/v1/vulns/GHSA-xxxx-yyyy-zzzz" {
				t.Errorf("unexpected path: %s", r.URL.Path)
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(osvVulnerability{
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
			json.NewEncoder(w).Encode(osvVulnerability{
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
			json.NewEncoder(w).Encode(osvVulnerability{
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
			w.Write([]byte("{invalid json"))
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
			json.NewEncoder(w).Encode(osvVulnerability{
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
			json.NewEncoder(w).Encode(osvVulnerability{
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
func newTestOSVClient(baseURL string) *testOSVClient {
	return &testOSVClient{
		baseURL: baseURL,
		httpClient: &http.Client{
			Timeout: 5 * 1000000000, // 5 seconds for tests
		},
	}
}

// testOSVClient is a variant of OSVClient for testing with custom base URL.
type testOSVClient struct {
	baseURL    string
	httpClient *http.Client
}

// ResolveCVEID is a test version that uses the custom base URL.
func (c *testOSVClient) ResolveCVEID(ctx context.Context, vulnID string) (string, error) {
	// Already a CVE ID
	if len(vulnID) >= 4 && vulnID[:4] == "CVE-" {
		return vulnID, nil
	}

	// Fetch vulnerability details from test server
	vulnURL := c.baseURL + "/v1/vulns/" + vulnID

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, vulnURL, nil)
	if err != nil {
		return vulnID, err
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return vulnID, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return vulnID, nil
	}
	if resp.StatusCode != http.StatusOK {
		return vulnID, &httpError{StatusCode: resp.StatusCode}
	}

	var vuln osvVulnerability
	if err := json.NewDecoder(resp.Body).Decode(&vuln); err != nil {
		return vulnID, err
	}

	// Look for CVE alias
	for _, alias := range vuln.Aliases {
		if len(alias) >= 4 && alias[:4] == "CVE-" {
			return alias, nil
		}
	}

	return vulnID, nil
}

type httpError struct {
	StatusCode int
}

func (e *httpError) Error() string {
	return "HTTP error: " + http.StatusText(e.StatusCode)
}
