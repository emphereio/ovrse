package intel

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/emphereio/ovrse/pkg/auth"
)

func newTestKeypair(t *testing.T) *auth.Keypair {
	kp, err := auth.GenerateKeypair()
	if err != nil {
		t.Fatalf("failed to generate keypair: %v", err)
	}
	return kp
}

func TestAnalyzeCVE(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify request
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/v1/analyze" {
			t.Errorf("expected /v1/analyze, got %s", r.URL.Path)
		}
		if r.Header.Get("Authorization") == "" {
			t.Error("expected Authorization header")
		}

		// Decode request body
		var req AnalyzeCVERequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("failed to decode request: %v", err)
		}
		if req.CVEID != "CVE-2021-44228" {
			t.Errorf("expected CVE-2021-44228, got %s", req.CVEID)
		}

		// Return response matching intel-engine format
		toVersion := "4.17.21"
		resp := AnalyzeCVEResponse{
			CVEID:      "CVE-2021-44228",
			Action:     "fix_now",
			CanAutoFix: true,
			Fix: &FixInfo{
				Command:   "npm install lodash@4.17.21",
				ToVersion: &toVersion,
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewClient(newTestKeypair(t), WithBaseURL(server.URL))

	resp, err := client.AnalyzeCVE(context.Background(), &AnalyzeCVERequest{
		CVEID: "CVE-2021-44228",
	})
	if err != nil {
		t.Fatalf("AnalyzeCVE failed: %v", err)
	}

	if resp.Action != "fix_now" {
		t.Errorf("expected action fix_now, got %s", resp.Action)
	}
	if !resp.CanAutoFix {
		t.Error("expected can_auto_fix to be true")
	}
	if resp.Fix == nil || resp.Fix.Command == "" {
		t.Error("expected fix command")
	}
	if resp.CVEID != "CVE-2021-44228" {
		t.Errorf("expected cve_id CVE-2021-44228, got %s", resp.CVEID)
	}
}

func TestGetCVEVerdict(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("expected GET, got %s", r.Method)
		}
		if r.URL.Path != "/v1/verdict/CVE-2021-44228" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}

		resp := VerdictResponse{
			CVEID:   "CVE-2021-44228",
			Verdict: "patch_immediately",
			Cached:  true,
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewClient(newTestKeypair(t), WithBaseURL(server.URL))

	resp, err := client.GetCVEVerdict(context.Background(), "CVE-2021-44228")
	if err != nil {
		t.Fatalf("GetCVEVerdict failed: %v", err)
	}

	if resp.Verdict != "patch_immediately" {
		t.Errorf("expected verdict patch_immediately, got %s", resp.Verdict)
	}
	if resp.CVEID != "CVE-2021-44228" {
		t.Errorf("expected cve_id CVE-2021-44228, got %s", resp.CVEID)
	}
}

func TestBatchTriage(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/v1/batch-triage" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}

		var req BatchTriageRequest
		_ = json.NewDecoder(r.Body).Decode(&req)

		resp := BatchTriageResponse{
			Summary: TriageSummary{
				Total:            2,
				PatchImmediately: 1,
			},
			Results: []VerdictResponse{
				{CVEID: req.CVEIDs[0], Verdict: "patch_immediately"},
				{CVEID: req.CVEIDs[1], Verdict: "defer"},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewClient(newTestKeypair(t), WithBaseURL(server.URL))

	resp, err := client.BatchTriage(context.Background(), []string{"CVE-2021-44228", "CVE-2020-1234"})
	if err != nil {
		t.Fatalf("BatchTriage failed: %v", err)
	}

	if resp.Summary.PatchImmediately != 1 {
		t.Errorf("expected 1 patch_immediately, got %d", resp.Summary.PatchImmediately)
	}
	if len(resp.Results) != 2 {
		t.Errorf("expected 2 results, got %d", len(resp.Results))
	}
}

func TestCheckIfAffected(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/v1/check-affected" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}

		var req CheckAffectedRequest
		_ = json.NewDecoder(r.Body).Decode(&req)

		fixVersion := "4.17.21"
		resp := CheckAffectedResponse{
			CVEID:          req.CVEID,
			PackageName:    req.PackageName,
			CurrentVersion: req.CurrentVersion,
			Ecosystem:      req.Ecosystem,
			Status:         "vulnerable",
			Action:         "upgrade_recommended",
			FixVersion:     &fixVersion,
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewClient(newTestKeypair(t), WithBaseURL(server.URL))

	resp, err := client.CheckIfAffected(context.Background(), &CheckAffectedRequest{
		CVEID:          "CVE-2021-23337",
		PackageName:    "lodash",
		CurrentVersion: "4.17.15",
		Ecosystem:      "npm",
	})
	if err != nil {
		t.Fatalf("CheckIfAffected failed: %v", err)
	}

	if resp.Status != "vulnerable" {
		t.Errorf("expected status vulnerable, got %s", resp.Status)
	}
	if resp.FixVersion == nil || *resp.FixVersion != "4.17.21" {
		t.Error("expected fix version 4.17.21")
	}
	if resp.CVEID != "CVE-2021-23337" {
		t.Errorf("expected cve_id CVE-2021-23337, got %s", resp.CVEID)
	}
}

func TestReportOutcome(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/v1/feedback" {
			t.Errorf("expected /v1/feedback, got %s", r.URL.Path)
		}

		message := "Outcome recorded"
		feedbackID := "fb_123"
		cveID := "CVE-2021-23337"
		pkgName := "lodash"
		outcome := "success"
		resp := ReportOutcomeResponse{
			Success:     true,
			FeedbackID:  &feedbackID,
			Message:     &message,
			CVEID:       &cveID,
			PackageName: &pkgName,
			Outcome:     &outcome,
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewClient(newTestKeypair(t), WithBaseURL(server.URL))

	resp, err := client.ReportOutcome(context.Background(), &ReportOutcomeRequest{
		CVEID:       "CVE-2021-23337",
		PackageName: "lodash",
		Ecosystem:   "npm",
		FromVersion: "4.17.15",
		ToVersion:   "4.17.21",
		Outcome:     "success",
	})
	if err != nil {
		t.Fatalf("ReportOutcome failed: %v", err)
	}

	if !resp.Success {
		t.Error("expected success to be true")
	}
	if resp.FeedbackID == nil || *resp.FeedbackID != "fb_123" {
		t.Error("expected feedback_id fb_123")
	}
}

func TestAPIError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(APIError{
			Error:   "invalid_request",
			Message: "CVE ID is required",
		})
	}))
	defer server.Close()

	client := NewClient(newTestKeypair(t), WithBaseURL(server.URL))

	_, err := client.GetCVEVerdict(context.Background(), "")
	if err == nil {
		t.Error("expected error for bad request")
	}
}

func TestPing(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/health" {
			t.Errorf("expected /v1/health, got %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := NewClient(newTestKeypair(t), WithBaseURL(server.URL))

	err := client.Ping(context.Background())
	if err != nil {
		t.Fatalf("Ping failed: %v", err)
	}
}

func TestClientOptions(t *testing.T) {
	kp := newTestKeypair(t)

	// Test WithBaseURL
	c1 := NewClient(kp, WithBaseURL("https://custom.api.dev"))
	if c1.baseURL != "https://custom.api.dev" {
		t.Errorf("expected custom base URL, got %s", c1.baseURL)
	}

	// Test default base URL
	c2 := NewClient(kp)
	if c2.baseURL != DefaultBaseURL {
		t.Errorf("expected default base URL %s, got %s", DefaultBaseURL, c2.baseURL)
	}
}

func TestTokenCaching(t *testing.T) {
	var tokensSeen []string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader != "" {
			tokensSeen = append(tokensSeen, authHeader)
		}

		resp := VerdictResponse{
			CVEID:   "CVE-2021-44228",
			Verdict: "patch_immediately",
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewClient(newTestKeypair(t), WithBaseURL(server.URL))

	// Make multiple requests
	for i := 0; i < 5; i++ {
		_, err := client.GetCVEVerdict(context.Background(), "CVE-2021-44228")
		if err != nil {
			t.Fatalf("request %d failed: %v", i, err)
		}
	}

	// All tokens should be the same (cached)
	if len(tokensSeen) != 5 {
		t.Fatalf("expected 5 tokens, got %d", len(tokensSeen))
	}

	firstToken := tokensSeen[0]
	for i, token := range tokensSeen {
		if token != firstToken {
			t.Errorf("request %d used different token (caching failed)", i)
		}
	}
}
