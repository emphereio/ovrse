package mcp

import (
	"encoding/json"
	"fmt"
	"regexp"

	"github.com/mark3labs/mcp-go/mcp"
)

// cveIDRegex validates CVE ID format: CVE-YYYY-NNNNN (where NNNNN is 4+ digits)
var cveIDRegex = regexp.MustCompile(`^CVE-\d{4}-\d{4,}$`)

// vulnIDRegex matches vulnerability ID formats.
// Accepts any alphanumeric ID with hyphens (e.g., CVE-2024-1234, GHSA-xxxx-xxxx-xxxx, RUSTSEC-2024-001).
// OSV will validate the actual ID; we just ensure basic format safety.
var vulnIDRegex = regexp.MustCompile(`^[A-Za-z0-9][-A-Za-z0-9]*$`)

// validateCVEID checks if a CVE ID has the correct format.
func validateCVEID(id string) error {
	if id == "" {
		return fmt.Errorf("CVE ID is required")
	}
	if !cveIDRegex.MatchString(id) {
		return fmt.Errorf("invalid CVE ID format: %s (expected CVE-YYYY-NNNNN)", id)
	}
	return nil
}

// validateVulnID checks if a vulnerability ID has a valid format.
// Accepts any alphanumeric ID with hyphens (CVE, GHSA, PYSEC, GO, RUSTSEC, etc.)
func validateVulnID(id string) error {
	if id == "" {
		return fmt.Errorf("vulnerability ID is required")
	}
	if !vulnIDRegex.MatchString(id) {
		return fmt.Errorf("invalid vulnerability ID format: %s (expected alphanumeric ID like CVE-2024-1234 or GHSA-xxxx-xxxx-xxxx)", id)
	}
	return nil
}

// isCVEID returns true if the ID is already in CVE format.
func isCVEID(id string) bool {
	return cveIDRegex.MatchString(id)
}

// Version is the ovrse version.
// Set via ldflags at build time: -ldflags "-X github.com/emphereio/ovrse/pkg/mcp.Version=x.y.z"
// Falls back to "dev" for local builds without ldflags.
var Version = "dev"

// ServerName is the MCP server name.
const ServerName = "ovrse"

// parseArgs parses tool arguments into a struct.
func parseArgs[T any](request mcp.CallToolRequest) (*T, error) {
	argsJSON, err := json.Marshal(request.Params.Arguments)
	if err != nil {
		return nil, err
	}
	var args T
	if err := json.Unmarshal(argsJSON, &args); err != nil {
		return nil, err
	}
	return &args, nil
}

// textResult creates a text content result.
func textResult(text string) *mcp.CallToolResult {
	return &mcp.CallToolResult{
		Content: []mcp.Content{
			mcp.NewTextContent(text),
		},
	}
}

// jsonResult creates a JSON content result.
// On JSON encoding error, returns an error result instead of propagating the error.
func jsonResult(data interface{}) (*mcp.CallToolResult, error) {
	jsonBytes, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		// Return error as result rather than propagating
		return errorResult(fmt.Errorf("JSON encoding failed: %w", err)), nil
	}
	return &mcp.CallToolResult{
		Content: []mcp.Content{
			mcp.NewTextContent(string(jsonBytes)),
		},
	}, nil
}

// errorResult creates an error result.
func errorResult(err error) *mcp.CallToolResult {
	return &mcp.CallToolResult{
		Content: []mcp.Content{
			mcp.NewTextContent("Error: " + err.Error()),
		},
		IsError: true,
	}
}
