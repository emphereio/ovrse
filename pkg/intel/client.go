package intel

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/emphereio/ovrse/pkg/auth"
)

const (
	// DefaultBaseURL is the default Intel-engine API endpoint.
	DefaultBaseURL = "https://api.emphere.dev"

	// DefaultTimeout is the default HTTP request timeout.
	DefaultTimeout = 30 * time.Second
)

// Client is an HTTP client for the Intel-engine API.
type Client struct {
	baseURL    string
	httpClient *http.Client
	keypair    *auth.Keypair
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
	err := c.post(ctx, "/v1/cve/analyze", req, &resp)
	if err != nil {
		return nil, err
	}
	return &resp, nil
}

// GetCVEVerdict performs quick verdict lookup.
func (c *Client) GetCVEVerdict(ctx context.Context, cveID string) (*VerdictResponse, error) {
	var resp VerdictResponse
	err := c.get(ctx, fmt.Sprintf("/v1/cve/%s/verdict", cveID), &resp)
	if err != nil {
		return nil, err
	}
	return &resp, nil
}

// BatchTriage triages multiple CVEs at once.
func (c *Client) BatchTriage(ctx context.Context, cveIDs []string) (*BatchTriageResponse, error) {
	req := &BatchTriageRequest{CVEIDs: cveIDs}
	var resp BatchTriageResponse
	err := c.post(ctx, "/v1/cve/batch-triage", req, &resp)
	if err != nil {
		return nil, err
	}
	return &resp, nil
}

// CheckIfAffected checks if a specific version is affected by a CVE.
func (c *Client) CheckIfAffected(ctx context.Context, req *CheckAffectedRequest) (*CheckAffectedResponse, error) {
	var resp CheckAffectedResponse
	err := c.post(ctx, "/v1/cve/check-affected", req, &resp)
	if err != nil {
		return nil, err
	}
	return &resp, nil
}

// ReportOutcome reports the outcome of a remediation attempt.
func (c *Client) ReportOutcome(ctx context.Context, req *ReportOutcomeRequest) (*ReportOutcomeResponse, error) {
	var resp ReportOutcomeResponse
	err := c.post(ctx, "/v1/cve/report-outcome", req, &resp)
	if err != nil {
		return nil, err
	}
	return &resp, nil
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
	url := c.baseURL + path

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

	// Add JWT authentication
	if c.keypair != nil {
		token, err := c.keypair.SignJWT()
		if err != nil {
			return fmt.Errorf("failed to sign JWT: %w", err)
		}
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	// Read response body
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	// Check for errors
	if resp.StatusCode >= 400 {
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
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/health", nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to reach API: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("API returned status %d", resp.StatusCode)
	}

	return nil
}
