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
		if r.URL.Path != "/v1/cve/analyze" {
			t.Errorf("expected /v1/cve/analyze, got %s", r.URL.Path)
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

		// Return response
		resp := AnalyzeCVEResponse{
			Action:     "fix_now",
			CanAutoFix: true,
			Fix: &FixInfo{
				Command:    "npm install lodash@4.17.21",
				FixVersion: "4.17.21",
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
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
}

func TestGetCVEVerdict(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("expected GET, got %s", r.Method)
		}
		if r.URL.Path != "/v1/cve/CVE-2021-44228/verdict" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}

		resp := VerdictResponse{
			Verdict: "patch_immediately",
			Cached:  true,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
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
}

func TestBatchTriage(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/v1/cve/batch-triage" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}

		var req BatchTriageRequest
		json.NewDecoder(r.Body).Decode(&req)

		resp := BatchTriageResponse{
			Summary: TriageSummary{
				PatchImmediately: 1,
				Defer:            1,
			},
			Results: []VerdictResult{
				{CVEID: req.CVEIDs[0], Verdict: "patch_immediately"},
				{CVEID: req.CVEIDs[1], Verdict: "defer"},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
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

		var req CheckAffectedRequest
		json.NewDecoder(r.Body).Decode(&req)

		fixVersion := "4.17.21"
		resp := CheckAffectedResponse{
			Status:     "vulnerable",
			Action:     "upgrade_recommended",
			FixVersion: &fixVersion,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
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
}

func TestReportOutcome(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}

		resp := ReportOutcomeResponse{
			Success: true,
			Message: "Outcome recorded",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
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
}

func TestAPIError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(APIError{
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
		if r.URL.Path != "/health" {
			t.Errorf("expected /health, got %s", r.URL.Path)
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
