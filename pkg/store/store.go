package store

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

// Store provides SQLite storage for Overseer data.
type Store struct {
	db   *sql.DB
	path string
}

// DefaultDBPath returns the default database path (~/.local/share/ovrse/overseer.db).
// Uses XDG_DATA_HOME on Linux/macOS, LocalAppData on Windows.
func DefaultDBPath() (string, error) {
	var baseDir string

	// Check XDG_DATA_HOME first (Linux/macOS)
	if dir := os.Getenv("XDG_DATA_HOME"); dir != "" {
		baseDir = dir
	} else if dir := os.Getenv("LOCALAPPDATA"); dir != "" {
		// Windows
		baseDir = dir
	} else {
		// Default: ~/.local/share
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("failed to get home dir: %w", err)
		}
		baseDir = filepath.Join(home, ".local", "share")
	}

	return filepath.Join(baseDir, "ovrse", "overseer.db"), nil
}

// New creates a new Store with the given database path.
// If dbPath is empty, uses the default path.
func New(dbPath string) (*Store, error) {
	if dbPath == "" {
		var err error
		dbPath, err = DefaultDBPath()
		if err != nil {
			return nil, err
		}
	}

	// Ensure parent directory exists
	dir := filepath.Dir(dbPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create database directory: %w", err)
	}

	// Open database with WAL mode for better concurrency
	db, err := sql.Open("sqlite3", dbPath+"?_journal_mode=WAL&_foreign_keys=ON")
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Test connection
	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	s := &Store{db: db, path: dbPath}

	// Initialize schema
	if err := s.initSchema(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("failed to initialize schema: %w", err)
	}

	return s, nil
}

// Close closes the database connection.
func (s *Store) Close() error {
	return s.db.Close()
}

// Path returns the database file path.
func (s *Store) Path() string {
	return s.path
}

// initSchema creates tables and runs migrations.
func (s *Store) initSchema() error {
	// Create tables
	if _, err := s.db.Exec(schema); err != nil {
		return fmt.Errorf("failed to create schema: %w", err)
	}

	// Check current version and run migrations
	var version int
	err := s.db.QueryRow("SELECT version FROM schema_version ORDER BY version DESC LIMIT 1").Scan(&version)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("failed to get schema version: %w", err)
	}

	// Run pending migrations
	for v := version; v < currentSchemaVersion; v++ {
		if migration, ok := migrations[v]; ok {
			if _, err := s.db.Exec(migration); err != nil {
				return fmt.Errorf("failed to run migration %d: %w", v, err)
			}
			if _, err := s.db.Exec("INSERT INTO schema_version (version) VALUES (?)", v+1); err != nil {
				return fmt.Errorf("failed to update schema version: %w", err)
			}
		}
	}

	return nil
}

// ============================================================================
// Project Operations
// ============================================================================

// AddProject adds a new project to monitor.
func (s *Store) AddProject(path string) (*Project, error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve path: %w", err)
	}

	name := filepath.Base(absPath)

	result, err := s.db.Exec(
		"INSERT INTO projects (path, name) VALUES (?, ?) ON CONFLICT(path) DO NOTHING",
		absPath, name,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to add project: %w", err)
	}

	// Check if inserted or already existed
	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		// Already exists, fetch it
		return s.GetProjectByPath(absPath)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return nil, fmt.Errorf("failed to get project ID: %w", err)
	}

	return s.GetProject(id)
}

// GetProject retrieves a project by ID.
func (s *Store) GetProject(id int64) (*Project, error) {
	p := &Project{}
	var lastScanned sql.NullTime
	var ecosystem sql.NullString
	err := s.db.QueryRow(
		"SELECT id, path, name, ecosystem, added_at, last_scanned_at FROM projects WHERE id = ?",
		id,
	).Scan(&p.ID, &p.Path, &p.Name, &ecosystem, &p.AddedAt, &lastScanned)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get project: %w", err)
	}
	if lastScanned.Valid {
		p.LastScannedAt = &lastScanned.Time
	}
	if ecosystem.Valid {
		p.Ecosystem = ecosystem.String
	}
	return p, nil
}

// GetProjectByPath retrieves a project by its path.
func (s *Store) GetProjectByPath(path string) (*Project, error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve path: %w", err)
	}

	p := &Project{}
	var lastScanned sql.NullTime
	var ecosystem sql.NullString
	err = s.db.QueryRow(
		"SELECT id, path, name, ecosystem, added_at, last_scanned_at FROM projects WHERE path = ?",
		absPath,
	).Scan(&p.ID, &p.Path, &p.Name, &ecosystem, &p.AddedAt, &lastScanned)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get project: %w", err)
	}
	if lastScanned.Valid {
		p.LastScannedAt = &lastScanned.Time
	}
	if ecosystem.Valid {
		p.Ecosystem = ecosystem.String
	}
	return p, nil
}

// ListProjects returns all monitored projects.
func (s *Store) ListProjects() ([]Project, error) {
	rows, err := s.db.Query(
		"SELECT id, path, name, ecosystem, added_at, last_scanned_at FROM projects ORDER BY name",
	)
	if err != nil {
		return nil, fmt.Errorf("failed to list projects: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var projects []Project
	for rows.Next() {
		p := Project{}
		var lastScanned sql.NullTime
		var ecosystem sql.NullString
		if err := rows.Scan(&p.ID, &p.Path, &p.Name, &ecosystem, &p.AddedAt, &lastScanned); err != nil {
			return nil, fmt.Errorf("failed to scan project: %w", err)
		}
		if lastScanned.Valid {
			p.LastScannedAt = &lastScanned.Time
		}
		if ecosystem.Valid {
			p.Ecosystem = ecosystem.String
		}
		projects = append(projects, p)
	}
	return projects, rows.Err()
}

// RemoveProject removes a project and all its data.
func (s *Store) RemoveProject(path string) error {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("failed to resolve path: %w", err)
	}

	_, err = s.db.Exec("DELETE FROM projects WHERE path = ?", absPath)
	if err != nil {
		return fmt.Errorf("failed to remove project: %w", err)
	}
	return nil
}

// UpdateProjectScanTime updates the last scanned timestamp for a project.
func (s *Store) UpdateProjectScanTime(projectID int64) error {
	_, err := s.db.Exec(
		"UPDATE projects SET last_scanned_at = CURRENT_TIMESTAMP WHERE id = ?",
		projectID,
	)
	return err
}

// UpdateProjectEcosystem updates the ecosystem for a project.
func (s *Store) UpdateProjectEcosystem(projectID int64, ecosystem string) error {
	_, err := s.db.Exec(
		"UPDATE projects SET ecosystem = ? WHERE id = ?",
		ecosystem, projectID,
	)
	return err
}

// ============================================================================
// Package Operations
// ============================================================================

// UpsertPackage inserts or updates a package in a project.
// Unique key is (project_id, name, version, ecosystem) to support multiple versions.
func (s *Store) UpsertPackage(pkg Package) (*Package, error) {
	result, err := s.db.Exec(`
		INSERT INTO packages (project_id, name, version, ecosystem, lock_file)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(project_id, name, version, ecosystem) DO UPDATE SET
			lock_file = excluded.lock_file
	`, pkg.ProjectID, pkg.Name, pkg.Version, pkg.Ecosystem, pkg.LockFile)
	if err != nil {
		return nil, fmt.Errorf("failed to upsert package: %w", err)
	}

	id, _ := result.LastInsertId()
	if id == 0 {
		// Was an update, fetch the existing ID
		err = s.db.QueryRow(
			"SELECT id FROM packages WHERE project_id = ? AND name = ? AND version = ? AND ecosystem = ?",
			pkg.ProjectID, pkg.Name, pkg.Version, pkg.Ecosystem,
		).Scan(&id)
		if err != nil {
			return nil, fmt.Errorf("failed to get package ID: %w", err)
		}
	}

	pkg.ID = id
	return &pkg, nil
}

// GetPackagesByProject returns all packages for a project.
func (s *Store) GetPackagesByProject(projectID int64) ([]Package, error) {
	rows, err := s.db.Query(
		"SELECT id, project_id, name, version, ecosystem, lock_file FROM packages WHERE project_id = ?",
		projectID,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to get packages: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var packages []Package
	for rows.Next() {
		p := Package{}
		var lockFile sql.NullString
		if err := rows.Scan(&p.ID, &p.ProjectID, &p.Name, &p.Version, &p.Ecosystem, &lockFile); err != nil {
			return nil, fmt.Errorf("failed to scan package: %w", err)
		}
		if lockFile.Valid {
			p.LockFile = lockFile.String
		}
		packages = append(packages, p)
	}
	return packages, rows.Err()
}

// ClearPackagesForProject removes all packages for a project (before re-scanning).
func (s *Store) ClearPackagesForProject(projectID int64) error {
	_, err := s.db.Exec("DELETE FROM packages WHERE project_id = ?", projectID)
	return err
}

// ============================================================================
// Vulnerability Operations
// ============================================================================

// RecordVulnerability records a vulnerability for a package.
func (s *Store) RecordVulnerability(vuln Vulnerability) (*Vulnerability, error) {
	var cvssScore interface{}
	if vuln.CVSSScore != nil {
		cvssScore = *vuln.CVSSScore
	}

	result, err := s.db.Exec(`
		INSERT INTO vulnerabilities (package_id, cve_id, severity, cvss_score, summary, fix_version)
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT(package_id, cve_id) DO UPDATE SET
			severity = excluded.severity,
			cvss_score = excluded.cvss_score,
			summary = excluded.summary,
			fix_version = excluded.fix_version
	`, vuln.PackageID, vuln.CVEID, vuln.Severity, cvssScore, vuln.Summary, vuln.FixVersion)
	if err != nil {
		return nil, fmt.Errorf("failed to record vulnerability: %w", err)
	}

	id, _ := result.LastInsertId()
	if id == 0 {
		err = s.db.QueryRow(
			"SELECT id FROM vulnerabilities WHERE package_id = ? AND cve_id = ?",
			vuln.PackageID, vuln.CVEID,
		).Scan(&id)
		if err != nil {
			return nil, fmt.Errorf("failed to get vulnerability ID: %w", err)
		}
	}

	vuln.ID = id
	return &vuln, nil
}

// ListVulnerabilities returns vulnerabilities matching the filter.
func (s *Store) ListVulnerabilities(filter VulnFilter) ([]VulnResult, error) {
	query := `
		SELECT
			v.id, v.package_id, v.cve_id, v.severity, v.cvss_score,
			v.summary, v.fix_version, v.detected_at, v.dismissed_at,
			p.name, p.version, p.ecosystem,
			pr.path, pr.name
		FROM vulnerabilities v
		JOIN packages p ON v.package_id = p.id
		JOIN projects pr ON p.project_id = pr.id
		WHERE 1=1
	`
	var args []interface{}

	if filter.ProjectID != nil {
		query += " AND pr.id = ?"
		args = append(args, *filter.ProjectID)
	}
	if filter.ProjectPath != "" {
		absPath, _ := filepath.Abs(filter.ProjectPath)
		query += " AND pr.path = ?"
		args = append(args, absPath)
	}
	if len(filter.Severity) > 0 {
		placeholders := make([]string, len(filter.Severity))
		for i, sev := range filter.Severity {
			placeholders[i] = "?"
			args = append(args, sev)
		}
		query += " AND v.severity IN (" + strings.Join(placeholders, ",") + ")"
	}
	if filter.CVEID != "" {
		query += " AND v.cve_id = ?"
		args = append(args, filter.CVEID)
	}
	if filter.Dismissed != nil {
		if *filter.Dismissed {
			query += " AND v.dismissed_at IS NOT NULL"
		} else {
			query += " AND v.dismissed_at IS NULL"
		}
	}

	query += " ORDER BY CASE v.severity WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2 WHEN 'MEDIUM' THEN 3 WHEN 'LOW' THEN 4 ELSE 5 END, v.detected_at DESC"

	if filter.Limit > 0 {
		query += " LIMIT ?"
		args = append(args, filter.Limit)
	}

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to list vulnerabilities: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var results []VulnResult
	for rows.Next() {
		r := VulnResult{}
		var cvssScore sql.NullFloat64
		var summary, fixVersion sql.NullString
		var dismissedAt sql.NullTime
		var projectName sql.NullString

		if err := rows.Scan(
			&r.ID, &r.PackageID, &r.CVEID, &r.Severity, &cvssScore,
			&summary, &fixVersion, &r.DetectedAt, &dismissedAt,
			&r.PackageName, &r.PackageVersion, &r.PackageEco,
			&r.ProjectPath, &projectName,
		); err != nil {
			return nil, fmt.Errorf("failed to scan vulnerability: %w", err)
		}

		if cvssScore.Valid {
			r.CVSSScore = &cvssScore.Float64
		}
		if summary.Valid {
			r.Summary = summary.String
		}
		if fixVersion.Valid {
			r.FixVersion = fixVersion.String
		}
		if dismissedAt.Valid {
			r.DismissedAt = &dismissedAt.Time
		}
		if projectName.Valid {
			r.ProjectName = projectName.String
		}

		results = append(results, r)
	}
	return results, rows.Err()
}

// DismissVulnerability marks a vulnerability as dismissed.
func (s *Store) DismissVulnerability(vulnID int64) error {
	_, err := s.db.Exec(
		"UPDATE vulnerabilities SET dismissed_at = CURRENT_TIMESTAMP WHERE id = ?",
		vulnID,
	)
	return err
}

// UndismissVulnerability removes the dismissed status from a vulnerability.
func (s *Store) UndismissVulnerability(vulnID int64) error {
	_, err := s.db.Exec(
		"UPDATE vulnerabilities SET dismissed_at = NULL WHERE id = ?",
		vulnID,
	)
	return err
}

// ClearVulnerabilitiesForPackage removes all vulnerabilities for a package.
func (s *Store) ClearVulnerabilitiesForPackage(packageID int64) error {
	_, err := s.db.Exec("DELETE FROM vulnerabilities WHERE package_id = ?", packageID)
	return err
}

// GetVulnerabilityCount returns the total count of active vulnerabilities.
func (s *Store) GetVulnerabilityCount() (int, error) {
	var count int
	err := s.db.QueryRow("SELECT COUNT(*) FROM vulnerabilities WHERE dismissed_at IS NULL").Scan(&count)
	return count, err
}

// ============================================================================
// Scan Operations
// ============================================================================

// StartScan creates a new scan record.
func (s *Store) StartScan(projectID int64) (*Scan, error) {
	result, err := s.db.Exec(
		"INSERT INTO scans (project_id, status) VALUES (?, ?)",
		projectID, ScanStatusRunning,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to start scan: %w", err)
	}

	id, _ := result.LastInsertId()
	return &Scan{
		ID:        id,
		ProjectID: projectID,
		StartedAt: time.Now(),
		Status:    ScanStatusRunning,
	}, nil
}

// CompleteScan marks a scan as completed.
func (s *Store) CompleteScan(scanID int64, packagesScanned, vulnsFound int) error {
	_, err := s.db.Exec(`
		UPDATE scans SET
			completed_at = CURRENT_TIMESTAMP,
			packages_scanned = ?,
			vulns_found = ?,
			status = ?
		WHERE id = ?
	`, packagesScanned, vulnsFound, ScanStatusCompleted, scanID)
	return err
}

// FailScan marks a scan as failed.
func (s *Store) FailScan(scanID int64) error {
	_, err := s.db.Exec(`
		UPDATE scans SET
			completed_at = CURRENT_TIMESTAMP,
			status = ?
		WHERE id = ?
	`, ScanStatusFailed, scanID)
	return err
}

// GetLastScan returns the most recent scan for a project.
func (s *Store) GetLastScan(projectID int64) (*Scan, error) {
	scan := &Scan{}
	var completedAt sql.NullTime
	err := s.db.QueryRow(`
		SELECT id, project_id, started_at, completed_at, packages_scanned, vulns_found, status
		FROM scans WHERE project_id = ? ORDER BY started_at DESC LIMIT 1
	`, projectID).Scan(
		&scan.ID, &scan.ProjectID, &scan.StartedAt, &completedAt,
		&scan.PackagesScanned, &scan.VulnsFound, &scan.Status,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get last scan: %w", err)
	}
	if completedAt.Valid {
		scan.CompletedAt = &completedAt.Time
	}
	return scan, nil
}

// ============================================================================
// Summary Operations
// ============================================================================

// GetProjectSummary returns vulnerability summary for a project.
func (s *Store) GetProjectSummary(projectID int64) (*ProjectSummary, error) {
	project, err := s.GetProject(projectID)
	if err != nil {
		return nil, err
	}
	if project == nil {
		return nil, nil
	}

	summary := &ProjectSummary{
		Project:    *project,
		BySeverity: make(map[string]int),
	}

	// Count packages
	err = s.db.QueryRow(
		"SELECT COUNT(*) FROM packages WHERE project_id = ?",
		projectID,
	).Scan(&summary.TotalPackages)
	if err != nil {
		return nil, fmt.Errorf("failed to count packages: %w", err)
	}

	// Count vulnerabilities by severity
	rows, err := s.db.Query(`
		SELECT COALESCE(v.severity, 'UNKNOWN'), COUNT(*)
		FROM vulnerabilities v
		JOIN packages p ON v.package_id = p.id
		WHERE p.project_id = ? AND v.dismissed_at IS NULL
		GROUP BY v.severity
	`, projectID)
	if err != nil {
		return nil, fmt.Errorf("failed to count vulnerabilities: %w", err)
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var severity string
		var count int
		if err := rows.Scan(&severity, &count); err != nil {
			return nil, fmt.Errorf("failed to scan severity count: %w", err)
		}
		summary.BySeverity[severity] = count
		summary.TotalVulns += count
	}

	return summary, rows.Err()
}

// GetOverallSummary returns vulnerability summary across all projects.
func (s *Store) GetOverallSummary() (map[string]int, int, error) {
	bySeverity := make(map[string]int)
	var total int

	rows, err := s.db.Query(`
		SELECT COALESCE(severity, 'UNKNOWN'), COUNT(*)
		FROM vulnerabilities
		WHERE dismissed_at IS NULL
		GROUP BY severity
	`)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to get summary: %w", err)
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var severity string
		var count int
		if err := rows.Scan(&severity, &count); err != nil {
			return nil, 0, fmt.Errorf("failed to scan: %w", err)
		}
		bySeverity[severity] = count
		total += count
	}

	return bySeverity, total, rows.Err()
}
