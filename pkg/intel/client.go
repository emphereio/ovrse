package intel

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/emphereio/ovrse/pkg/auth"
	"github.com/emphereio/ovrse/pkg/logging"
)

const (
	// DefaultBaseURL is the default Intel-engine MCP API endpoint.
	// MCP routes are at mcp.emphere.dev/v1/* (not api.emphere.dev/v1/intel/*)
	DefaultBaseURL = "https://mcp.emphere.dev"

	// DefaultTimeout is the default HTTP request timeout.
	// AI analysis of new CVEs can take 30s-2min, so we use a generous timeout.
	DefaultTimeout = 180 * time.Second
)

// Client is an HTTP client for the Intel-engine API.
type Client struct {
	baseURL    string
	httpClient *http.Client
	keypair    *auth.Keypair

	// JWT token caching (tokens valid 5 min, refresh 30s before expiry)
	tokenMu     sync.RWMutex
	cachedToken string
	tokenExpiry time.Time
}

// ClientOption configures a Client.
type ClientOption func(*Client)

// WithBaseURL sets a custom base URL.
func WithBaseURL(url string) ClientOption {
	return func(c *Client) {
		c.baseURL = url
	}
}

// WithTimeout sets a custom HTTP timeout.
func WithTimeout(timeout time.Duration) ClientOption {
	return func(c *Client) {
		c.httpClient.Timeout = timeout
	}
}

// WithHTTPClient sets a custom HTTP client.
func WithHTTPClient(client *http.Client) ClientOption {
	return func(c *Client) {
		c.httpClient = client
	}
}

// NewClient creates a new Intel-engine API client.
func NewClient(keypair *auth.Keypair, opts ...ClientOption) *Client {
	c := &Client{
		baseURL: DefaultBaseURL,
		httpClient: &http.Client{
			Timeout: DefaultTimeout,
		},
		keypair: keypair,
	}

	for _, opt := range opts {
		opt(c)
	}

	return c
}

// AnalyzeCVE performs full CVE analysis.
func (c *Client) AnalyzeCVE(ctx context.Context, req *AnalyzeCVERequest) (*AnalyzeCVEResponse, error) {
	var resp AnalyzeCVEResponse
	err := c.post(ctx, "/v1/analyze", req, &resp)
	if err != nil {
		return nil, err
	}
	return &resp, nil
}

// GetCVEVerdict performs quick verdict lookup.
func (c *Client) GetCVEVerdict(ctx context.Context, cveID string) (*VerdictResponse, error) {
	var resp VerdictResponse
	err := c.get(ctx, fmt.Sprintf("/v1/verdict/%s", cveID), &resp)
	if err != nil {
		return nil, err
	}
	return &resp, nil
}

// BatchTriage triages multiple CVEs at once.
func (c *Client) BatchTriage(ctx context.Context, cveIDs []string) (*BatchTriageResponse, error) {
	req := &BatchTriageRequest{CVEIDs: cveIDs}
	var resp BatchTriageResponse
	err := c.post(ctx, "/v1/batch-triage", req, &resp)
	if err != nil {
		return nil, err
	}
	return &resp, nil
}

// CheckIfAffected checks if a specific version is affected by a CVE.
func (c *Client) CheckIfAffected(ctx context.Context, req *CheckAffectedRequest) (*CheckAffectedResponse, error) {
	var resp CheckAffectedResponse
	err := c.post(ctx, "/v1/check-affected", req, &resp)
	if err != nil {
		return nil, err
	}
	return &resp, nil
}

// ReportOutcome reports the outcome of a remediation attempt.
// Note: The intel-engine MCP endpoint is /v1/feedback (not report-outcome)
func (c *Client) ReportOutcome(ctx context.Context, req *ReportOutcomeRequest) (*ReportOutcomeResponse, error) {
	var resp ReportOutcomeResponse
	err := c.post(ctx, "/v1/feedback", req, &resp)
	if err != nil {
		return nil, err
	}
	return &resp, nil
}

// tokenRefreshBuffer is how long before expiry to refresh the token.
const tokenRefreshBuffer = 30 * time.Second

// getToken returns a valid JWT token, using cached value if still valid.
func (c *Client) getToken() (string, error) {
	if c.keypair == nil {
		return "", nil
	}

	// Check if we have a valid cached token (with buffer before expiry)
	c.tokenMu.RLock()
	if c.cachedToken != "" && time.Now().Add(tokenRefreshBuffer).Before(c.tokenExpiry) {
		token := c.cachedToken
		c.tokenMu.RUnlock()
		return token, nil
	}
	c.tokenMu.RUnlock()

	// Generate new token
	c.tokenMu.Lock()
	defer c.tokenMu.Unlock()

	// Double-check (another goroutine may have refreshed while we waited)
	if c.cachedToken != "" && time.Now().Add(tokenRefreshBuffer).Before(c.tokenExpiry) {
		return c.cachedToken, nil
	}

	token, err := c.keypair.SignJWT()
	if err != nil {
		return "", err
	}

	c.cachedToken = token
	c.tokenExpiry = time.Now().Add(auth.TokenExpiry)

	return token, nil
}

// get performs a GET request.
func (c *Client) get(ctx context.Context, path string, result interface{}) error {
	return c.doRequest(ctx, http.MethodGet, path, nil, result)
}

// post performs a POST request.
func (c *Client) post(ctx context.Context, path string, body, result interface{}) error {
	return c.doRequest(ctx, http.MethodPost, path, body, result)
}

// doRequest performs an HTTP request with JWT authentication.
func (c *Client) doRequest(ctx context.Context, method, path string, body, result interface{}) error {
	logger := logging.WithComponent("intel")
	url := c.baseURL + path
	start := time.Now()

	logger.Debug().
		Str("method", method).
		Str("path", path).
		Msg("sending API request")

	var reqBody io.Reader
	if body != nil {
		jsonBody, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("failed to marshal request: %w", err)
		}
		reqBody = bytes.NewReader(jsonBody)
	}

	req, err := http.NewRequestWithContext(ctx, method, url, reqBody)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "ovrse-cli/1.0")

	// Add JWT authentication (uses cached token when valid)
	token, err := c.getToken()
	if err != nil {
		return fmt.Errorf("failed to get JWT token: %w", err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		logger.Error().Err(err).Str("path", path).Msg("request failed")
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	logger.Debug().
		Int("status", resp.StatusCode).
		Dur("duration", time.Since(start)).
		Msg("received API response")

	// Read response body
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	// Check for errors
	if resp.StatusCode >= 400 {
		logger.Warn().
			Int("status", resp.StatusCode).
			Str("path", path).
			Msg("API error")
		var apiErr APIError
		if json.Unmarshal(respBody, &apiErr) == nil && (apiErr.Error != "" || apiErr.Detail != "") {
			errMsg := apiErr.Error
			if errMsg == "" {
				errMsg = apiErr.Detail
			}
			if apiErr.Message != "" {
				errMsg = errMsg + ": " + apiErr.Message
			}
			return fmt.Errorf("API error (status %d): %s", resp.StatusCode, errMsg)
		}
		return fmt.Errorf("API error (status %d): %s", resp.StatusCode, string(respBody))
	}

	// Decode response
	if result != nil && len(respBody) > 0 {
		if err := json.Unmarshal(respBody, result); err != nil {
			return fmt.Errorf("failed to decode response: %w", err)
		}
	}

	return nil
}

// Ping checks if the API is reachable.
func (c *Client) Ping(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/v1/health", nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to reach API: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("API returned status %d", resp.StatusCode)
	}

	return nil
}
