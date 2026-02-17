package store

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNew(t *testing.T) {
	// Create temp directory for test database
	tmpDir, err := os.MkdirTemp("", "ovrse-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	dbPath := filepath.Join(tmpDir, "test.db")
	store, err := New(dbPath)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer func() { _ = store.Close() }()

	if store.Path() != dbPath {
		t.Errorf("expected path %s, got %s", dbPath, store.Path())
	}
}

func TestProjectOperations(t *testing.T) {
	store := setupTestStore(t)
	defer func() { _ = store.Close() }()

	// Test AddProject
	project, err := store.AddProject("/test/project")
	if err != nil {
		t.Fatalf("failed to add project: %v", err)
	}
	if project.ID == 0 {
		t.Error("expected project ID to be set")
	}
	if project.Name != "project" {
		t.Errorf("expected name 'project', got '%s'", project.Name)
	}

	// Test GetProject
	fetched, err := store.GetProject(project.ID)
	if err != nil {
		t.Fatalf("failed to get project: %v", err)
	}
	if fetched.Path != project.Path {
		t.Errorf("expected path %s, got %s", project.Path, fetched.Path)
	}

	// Test GetProjectByPath
	fetched, err = store.GetProjectByPath("/test/project")
	if err != nil {
		t.Fatalf("failed to get project by path: %v", err)
	}
	if fetched.ID != project.ID {
		t.Errorf("expected ID %d, got %d", project.ID, fetched.ID)
	}

	// Test ListProjects
	projects, err := store.ListProjects()
	if err != nil {
		t.Fatalf("failed to list projects: %v", err)
	}
	if len(projects) != 1 {
		t.Errorf("expected 1 project, got %d", len(projects))
	}

	// Test AddProject idempotency
	project2, err := store.AddProject("/test/project")
	if err != nil {
		t.Fatalf("failed to add duplicate project: %v", err)
	}
	if project2.ID != project.ID {
		t.Error("expected same project ID for duplicate add")
	}

	// Test RemoveProject
	err = store.RemoveProject("/test/project")
	if err != nil {
		t.Fatalf("failed to remove project: %v", err)
	}
	projects, _ = store.ListProjects()
	if len(projects) != 0 {
		t.Error("expected 0 projects after removal")
	}
}

func TestPackageOperations(t *testing.T) {
	store := setupTestStore(t)
	defer func() { _ = store.Close() }()

	// Add a project first
	project, err := store.AddProject("/test/project")
	if err != nil {
		t.Fatalf("failed to add project: %v", err)
	}

	// Test UpsertPackage
	pkg := Package{
		ProjectID: project.ID,
		Name:      "lodash",
		Version:   "4.17.15",
		Ecosystem: "npm",
		LockFile:  "package-lock.json",
	}
	inserted, err := store.UpsertPackage(pkg)
	if err != nil {
		t.Fatalf("failed to upsert package: %v", err)
	}
	if inserted.ID == 0 {
		t.Error("expected package ID to be set")
	}

	// Test upsert same version updates lock_file (unique key includes version)
	pkg.LockFile = "updated-lock.json"
	updated, err := store.UpsertPackage(pkg)
	if err != nil {
		t.Fatalf("failed to update package: %v", err)
	}
	if updated.ID != inserted.ID {
		t.Error("expected same ID after update with same version")
	}

	// Test adding different version creates new row (npm can have multiple versions)
	pkg2 := Package{
		ProjectID: project.ID,
		Name:      "lodash",
		Version:   "4.17.21",
		Ecosystem: "npm",
		LockFile:  "package-lock.json",
	}
	inserted2, err := store.UpsertPackage(pkg2)
	if err != nil {
		t.Fatalf("failed to insert second version: %v", err)
	}
	if inserted2.ID == inserted.ID {
		t.Error("expected different ID for different version")
	}

	// Test GetPackagesByProject returns both versions
	packages, err := store.GetPackagesByProject(project.ID)
	if err != nil {
		t.Fatalf("failed to get packages: %v", err)
	}
	if len(packages) != 2 {
		t.Errorf("expected 2 packages (different versions), got %d", len(packages))
	}
}

func TestVulnerabilityOperations(t *testing.T) {
	store := setupTestStore(t)
	defer func() { _ = store.Close() }()

	// Setup project and package
	project, _ := store.AddProject("/test/project")
	pkg, _ := store.UpsertPackage(Package{
		ProjectID: project.ID,
		Name:      "lodash",
		Version:   "4.17.15",
		Ecosystem: "npm",
	})

	// Test RecordVulnerability
	cvss := 9.8
	vuln := Vulnerability{
		PackageID:  pkg.ID,
		CVEID:      "CVE-2021-23337",
		Severity:   SeverityHigh,
		CVSSScore:  &cvss,
		Summary:    "Prototype pollution",
		FixVersion: "4.17.21",
	}
	recorded, err := store.RecordVulnerability(vuln)
	if err != nil {
		t.Fatalf("failed to record vulnerability: %v", err)
	}
	if recorded.ID == 0 {
		t.Error("expected vulnerability ID to be set")
	}

	// Test ListVulnerabilities
	vulns, err := store.ListVulnerabilities(VulnFilter{})
	if err != nil {
		t.Fatalf("failed to list vulnerabilities: %v", err)
	}
	if len(vulns) != 1 {
		t.Errorf("expected 1 vulnerability, got %d", len(vulns))
	}
	if vulns[0].CVEID != "CVE-2021-23337" {
		t.Errorf("expected CVE-2021-23337, got %s", vulns[0].CVEID)
	}
	if vulns[0].PackageName != "lodash" {
		t.Errorf("expected package name lodash, got %s", vulns[0].PackageName)
	}

	// Test filter by severity
	vulns, _ = store.ListVulnerabilities(VulnFilter{Severity: []string{SeverityCritical}})
	if len(vulns) != 0 {
		t.Error("expected 0 vulnerabilities with CRITICAL filter")
	}

	// Test DismissVulnerability
	err = store.DismissVulnerability(recorded.ID)
	if err != nil {
		t.Fatalf("failed to dismiss vulnerability: %v", err)
	}

	dismissed := false
	vulns, _ = store.ListVulnerabilities(VulnFilter{Dismissed: &dismissed})
	if len(vulns) != 0 {
		t.Error("expected 0 active vulnerabilities after dismiss")
	}

	// Test GetVulnerabilityCount
	count, _ := store.GetVulnerabilityCount()
	if count != 0 {
		t.Errorf("expected 0 active vulns, got %d", count)
	}
}

func TestScanOperations(t *testing.T) {
	store := setupTestStore(t)
	defer func() { _ = store.Close() }()

	project, _ := store.AddProject("/test/project")

	// Test StartScan
	scan, err := store.StartScan(project.ID)
	if err != nil {
		t.Fatalf("failed to start scan: %v", err)
	}
	if scan.Status != ScanStatusRunning {
		t.Errorf("expected status %s, got %s", ScanStatusRunning, scan.Status)
	}

	// Test CompleteScan
	err = store.CompleteScan(scan.ID, 10, 2)
	if err != nil {
		t.Fatalf("failed to complete scan: %v", err)
	}

	// Test GetLastScan
	lastScan, err := store.GetLastScan(project.ID)
	if err != nil {
		t.Fatalf("failed to get last scan: %v", err)
	}
	if lastScan.Status != ScanStatusCompleted {
		t.Errorf("expected status %s, got %s", ScanStatusCompleted, lastScan.Status)
	}
	if lastScan.PackagesScanned != 10 {
		t.Errorf("expected 10 packages scanned, got %d", lastScan.PackagesScanned)
	}
}

func TestProjectSummary(t *testing.T) {
	store := setupTestStore(t)
	defer func() { _ = store.Close() }()

	// Setup project, package, and vulnerability
	project, _ := store.AddProject("/test/project")
	pkg, _ := store.UpsertPackage(Package{
		ProjectID: project.ID,
		Name:      "lodash",
		Version:   "4.17.15",
		Ecosystem: "npm",
	})
	_, _ = store.RecordVulnerability(Vulnerability{
		PackageID: pkg.ID,
		CVEID:     "CVE-2021-23337",
		Severity:  SeverityHigh,
	})
	_, _ = store.RecordVulnerability(Vulnerability{
		PackageID: pkg.ID,
		CVEID:     "CVE-2020-8203",
		Severity:  SeverityCritical,
	})

	// Test GetProjectSummary
	summary, err := store.GetProjectSummary(project.ID)
	if err != nil {
		t.Fatalf("failed to get project summary: %v", err)
	}
	if summary.TotalPackages != 1 {
		t.Errorf("expected 1 package, got %d", summary.TotalPackages)
	}
	if summary.TotalVulns != 2 {
		t.Errorf("expected 2 vulnerabilities, got %d", summary.TotalVulns)
	}
	if summary.BySeverity[SeverityHigh] != 1 {
		t.Errorf("expected 1 HIGH vuln, got %d", summary.BySeverity[SeverityHigh])
	}
	if summary.BySeverity[SeverityCritical] != 1 {
		t.Errorf("expected 1 CRITICAL vuln, got %d", summary.BySeverity[SeverityCritical])
	}
}

// setupTestStore creates a temporary test database.
func setupTestStore(t *testing.T) *Store {
	t.Helper()

	tmpDir, err := os.MkdirTemp("", "ovrse-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(tmpDir) })

	dbPath := filepath.Join(tmpDir, "test.db")
	store, err := New(dbPath)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}

	return store
}
