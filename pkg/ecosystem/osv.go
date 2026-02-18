package ecosystem

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/emphereio/ovrse/pkg/logging"
	"github.com/emphereio/ovrse/pkg/version"
)

const (
	osvAPIURL      = "https://api.osv.dev/v1"
	osvBatchQuery  = osvAPIURL + "/querybatch"

	// OSV batch API has a limit of 1000 queries per request.
	// We use 500 to stay well under the limit and reduce rate limiting.
	osvMaxBatchSize = 500

	// Delay between batch requests to avoid rate limiting.
	osvBatchDelay = 100 * time.Millisecond

	// Retry configuration for transient failures.
	osvMaxRetries     = 3
	osvInitialBackoff = 500 * time.Millisecond
)

// OSVClient queries the OSV.dev vulnerability database.
type OSVClient struct {
	httpClient *http.Client
}

// NewOSVClient creates a new OSV API client.
func NewOSVClient() *OSVClient {
	return &OSVClient{
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// DefaultOSVClient is a shared OSV client instance.
var DefaultOSVClient = NewOSVClient()

// CheckPackages queries OSV for vulnerabilities affecting the given packages.
// Large package lists are automatically chunked to avoid API limits.
func (c *OSVClient) CheckPackages(ctx context.Context, packages []Package) ([]Finding, error) {
	logger := logging.WithComponent("osv")

	if len(packages) == 0 {
		return nil, nil
	}

	logger.Debug().Int("package_count", len(packages)).Msg("querying OSV batch API")
	start := time.Now()

	// Chunk packages to stay under OSV batch limit
	var allFindings []Finding
	for i := 0; i < len(packages); i += osvMaxBatchSize {
		end := i + osvMaxBatchSize
		if end > len(packages) {
			end = len(packages)
		}
		chunk := packages[i:end]

		logger.Debug().
			Int("batch", i/osvMaxBatchSize+1).
			Int("batch_size", len(chunk)).
			Int("total_packages", len(packages)).
			Msg("processing batch")

		findings, err := c.queryBatchWithRetry(ctx, chunk)
		if err != nil {
			return nil, err
		}
		allFindings = append(allFindings, findings...)

		// Add delay between batches to avoid rate limiting
		if end < len(packages) {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(osvBatchDelay):
			}
		}
	}

	logger.Debug().
		Int("findings", len(allFindings)).
		Dur("duration", time.Since(start)).
		Msg("OSV query completed")

	return allFindings, nil
}

// queryBatchWithRetry queries a single batch with exponential backoff retry.
func (c *OSVClient) queryBatchWithRetry(ctx context.Context, packages []Package) ([]Finding, error) {
	logger := logging.WithComponent("osv")
	var lastErr error

	for attempt := 0; attempt < osvMaxRetries; attempt++ {
		if attempt > 0 {
			backoff := osvInitialBackoff * time.Duration(1<<(attempt-1))
			logger.Debug().
				Int("attempt", attempt+1).
				Dur("backoff", backoff).
				Msg("retrying OSV request")

			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(backoff):
			}
		}

		findings, err := c.queryBatch(ctx, packages)
		if err == nil {
			return findings, nil
		}

		lastErr = err
		// Only retry on transient errors (rate limiting, server errors)
		if !isRetryableError(err) {
			return nil, err
		}
		logger.Warn().Err(err).Int("attempt", attempt+1).Msg("OSV request failed, will retry")
	}

	return nil, fmt.Errorf("OSV request failed after %d attempts: %w", osvMaxRetries, lastErr)
}

// queryBatch performs a single batch query to OSV.
func (c *OSVClient) queryBatch(ctx context.Context, packages []Package) ([]Finding, error) {
	queries := make([]osvQuery, len(packages))
	for i, pkg := range packages {
		queries[i] = osvQuery{
			Package: osvPackage{
				Name:      pkg.Name,
				Ecosystem: pkg.Ecosystem,
			},
			Version: pkg.Version,
		}
	}

	reqBody, err := json.Marshal(osvBatchRequest{Queries: queries})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, osvBatchQuery, bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("OSV API error (status %d): %s", resp.StatusCode, string(body))
	}

	var batchResp osvBatchResponse
	if err := json.NewDecoder(resp.Body).Decode(&batchResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	// Map results back to packages
	var findings []Finding
	for i, result := range batchResp.Results {
		if i >= len(packages) {
			break
		}

		if len(result.Vulns) == 0 {
			continue
		}

		vulns := make([]Vulnerability, 0, len(result.Vulns))
		for _, v := range result.Vulns {
			vulns = append(vulns, convertOSVVuln(v))
		}

		findings = append(findings, Finding{
			Package:         packages[i],
			Vulnerabilities: vulns,
		})
	}

	return findings, nil
}

// isRetryableError returns true if the error is transient and worth retrying.
func isRetryableError(err error) bool {
	errStr := err.Error()
	// Retry on rate limiting (400 with "Too many queries", or 429)
	// and server errors (5xx)
	return strings.Contains(errStr, "Too many queries") ||
		strings.Contains(errStr, "status 429") ||
		strings.Contains(errStr, "status 500") ||
		strings.Contains(errStr, "status 502") ||
		strings.Contains(errStr, "status 503") ||
		strings.Contains(errStr, "status 504")
}

// convertOSVVuln converts an OSV vulnerability to our Vulnerability type.
func convertOSVVuln(v osvVulnerability) Vulnerability {
	vuln := Vulnerability{
		ID:      v.ID,
		Summary: v.Summary,
		Details: v.Details,
	}

	// Extract CVE aliases
	for _, alias := range v.Aliases {
		if strings.HasPrefix(alias, "CVE-") {
			vuln.Aliases = append(vuln.Aliases, alias)
		}
	}

	// Extract severity
	vuln.Severity, vuln.CVSSScore = extractSeverity(v)

	// Extract fix version
	vuln.FixVersion = extractFixVersion(v)

	// Extract references
	for _, ref := range v.References {
		vuln.References = append(vuln.References, ref.URL)
	}

	return vuln
}

func extractSeverity(v osvVulnerability) (string, *float64) {
	// Try database_specific first (more reliable for numeric scores)
	if v.DatabaseSpecific != nil {
		if severity, ok := v.DatabaseSpecific["severity"].(string); ok {
			return strings.ToUpper(severity), nil
		}
		if cvssScore, ok := v.DatabaseSpecific["cvss_score"].(float64); ok {
			return cvssToSeverity(cvssScore), &cvssScore
		}
	}

	// OSV severity field contains CVSS vectors, not numeric scores
	// Would need a CVSS library to parse - return UNKNOWN for MVP
	return "UNKNOWN", nil
}

func cvssToSeverity(score float64) string {
	switch {
	case score >= 9.0:
		return "CRITICAL"
	case score >= 7.0:
		return "HIGH"
	case score >= 4.0:
		return "MEDIUM"
	case score > 0:
		return "LOW"
	default:
		return "UNKNOWN"
	}
}

func extractFixVersion(v osvVulnerability) string {
	for _, affected := range v.Affected {
		for _, r := range affected.Ranges {
			for _, event := range r.Events {
				if event.Fixed != "" {
					return event.Fixed
				}
			}
		}
	}
	return ""
}

// OSV API types
type osvQuery struct {
	Package osvPackage `json:"package"`
	Version string     `json:"version"`
}

type osvPackage struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

type osvBatchRequest struct {
	Queries []osvQuery `json:"queries"`
}

type osvBatchResponse struct {
	Results []osvQueryResult `json:"results"`
}

type osvQueryResult struct {
	Vulns []osvVulnerability `json:"vulns"`
}

type osvVulnerability struct {
	ID               string                 `json:"id"`
	Summary          string                 `json:"summary"`
	Details          string                 `json:"details"`
	Aliases          []string               `json:"aliases"`
	Severity         []osvSeverity          `json:"severity"`
	Affected         []osvAffected          `json:"affected"`
	References       []osvReference         `json:"references"`
	DatabaseSpecific map[string]interface{} `json:"database_specific"`
}

type osvSeverity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

type osvAffected struct {
	Package osvPackage `json:"package"`
	Ranges  []osvRange `json:"ranges"`
}

type osvRange struct {
	Type   string     `json:"type"`
	Events []osvEvent `json:"events"`
}

type osvEvent struct {
	Introduced   string `json:"introduced,omitempty"`
	Fixed        string `json:"fixed,omitempty"`
	LastAffected string `json:"last_affected,omitempty"`
}

type osvReference struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

// AffectedResult represents the result of checking if a version is affected.
type AffectedResult struct {
	Status     version.VulnerabilityStatus `json:"status"`
	Message    string                      `json:"message"`
	VulnID     string                      `json:"vuln_id,omitempty"`
	FixVersion string                      `json:"fix_version,omitempty"`
	Severity   string                      `json:"severity,omitempty"`
}

// CheckIfAffected checks if a specific package version is affected by a vulnerability.
func (c *OSVClient) CheckIfAffected(ctx context.Context, vulnID string, pkg Package) (*AffectedResult, error) {
	// Query OSV for the vulnerability details
	vulnURL := fmt.Sprintf("%s/vulns/%s", osvAPIURL, vulnID)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, vulnURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch vulnerability: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotFound {
		return &AffectedResult{
			Status:  version.StatusUnknown,
			Message: fmt.Sprintf("vulnerability %s not found", vulnID),
		}, nil
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("OSV API error (status %d): %s", resp.StatusCode, string(body))
	}

	var vuln osvVulnerability
	if err := json.NewDecoder(resp.Body).Decode(&vuln); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	// Find the affected entry for this package
	return checkAffectedVersion(vuln, pkg)
}

// checkAffectedVersion checks if a package version is affected by a vulnerability.
func checkAffectedVersion(vuln osvVulnerability, pkg Package) (*AffectedResult, error) {
	result := &AffectedResult{
		VulnID: vuln.ID,
	}

	// Extract severity
	result.Severity, _ = extractSeverity(vuln)

	// Determine version format from ecosystem
	format := version.FormatForEcosystem(pkg.Ecosystem)

	// Find matching affected entry
	for _, affected := range vuln.Affected {
		// Check if this affected entry matches our package
		if !matchesPackage(affected.Package, pkg) {
			continue
		}

		// Check each range
		for _, r := range affected.Ranges {
			// Extract introduced, fixed, and lastAffected
			var introduced, fixed, lastAffected string
			for _, event := range r.Events {
				if event.Introduced != "" {
					introduced = event.Introduced
				}
				if event.Fixed != "" {
					fixed = event.Fixed
					result.FixVersion = fixed
				}
				if event.LastAffected != "" {
					lastAffected = event.LastAffected
				}
			}

			// Use version comparison to check status
			status, msg := version.CheckVulnerabilityStatus(
				pkg.Version,
				introduced,
				fixed,
				lastAffected,
				format,
			)

			result.Status = status
			result.Message = msg

			// If vulnerable, return immediately
			if status == version.StatusVulnerable {
				return result, nil
			}
		}
	}

	// If no matching affected entry found
	if result.Status == version.StatusUnknown {
		result.Status = version.StatusNotAffected
		result.Message = fmt.Sprintf("package %s not listed as affected", pkg.Name)
	}

	return result, nil
}

// matchesPackage checks if an OSV package matches our package.
func matchesPackage(osvPkg osvPackage, pkg Package) bool {
	// Normalize ecosystem names
	osvEco := strings.ToLower(osvPkg.Ecosystem)
	pkgEco := strings.ToLower(pkg.Ecosystem)

	// Check ecosystem match (with common aliases)
	ecoMatch := osvEco == pkgEco ||
		(osvEco == "npm" && pkgEco == "node") ||
		(osvEco == "pypi" && (pkgEco == "pip" || pkgEco == "python")) ||
		(osvEco == "go" && pkgEco == "golang")

	if !ecoMatch {
		return false
	}

	// Check package name match (case-insensitive for some ecosystems)
	osvName := strings.ToLower(osvPkg.Name)
	pkgName := strings.ToLower(pkg.Name)

	return osvName == pkgName
}

// ResolveCVEID resolves any vulnerability ID (GHSA, PYSEC, etc.) to its CVE alias.
// Returns the original ID if it's already a CVE or if no CVE alias exists.
func (c *OSVClient) ResolveCVEID(ctx context.Context, vulnID string) (string, error) {
	// Short-circuit for empty input
	vulnID = strings.TrimSpace(vulnID)
	if vulnID == "" {
		return "", nil
	}

	// Already a CVE ID
	if strings.HasPrefix(vulnID, "CVE-") {
		return vulnID, nil
	}

	// Fetch vulnerability details from OSV
	vulnURL := fmt.Sprintf("%s/vulns/%s", osvAPIURL, vulnID)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, vulnURL, nil)
	if err != nil {
		return vulnID, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return vulnID, fmt.Errorf("failed to fetch vulnerability: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotFound {
		// Vulnerability not found in OSV - return original ID
		return vulnID, nil
	}
	if resp.StatusCode != http.StatusOK {
		// Transient errors (429, 500, etc.) should be reported, not hidden
		return vulnID, fmt.Errorf("OSV API error (status %d)", resp.StatusCode)
	}

	var vuln osvVulnerability
	if err := json.NewDecoder(resp.Body).Decode(&vuln); err != nil {
		return vulnID, fmt.Errorf("failed to decode response: %w", err)
	}

	// Look for CVE alias
	for _, alias := range vuln.Aliases {
		if strings.HasPrefix(alias, "CVE-") {
			return alias, nil
		}
	}

	// No CVE alias found
	return vulnID, nil
}
