package store

// schema contains the SQL statements for creating the database tables.
const schema = `
-- Monitored projects
CREATE TABLE IF NOT EXISTS projects (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    path TEXT UNIQUE NOT NULL,
    name TEXT,
    ecosystem TEXT,
    added_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_scanned_at DATETIME
);

-- Index for fast path lookups
CREATE INDEX IF NOT EXISTS idx_projects_path ON projects(path);

-- Detected packages in projects
-- Note: UNIQUE includes version because npm/go can have multiple versions of same package
CREATE TABLE IF NOT EXISTS packages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    version TEXT NOT NULL,
    ecosystem TEXT NOT NULL,
    lock_file TEXT,
    UNIQUE(project_id, name, version, ecosystem)
);

-- Index for package lookups by project
CREATE INDEX IF NOT EXISTS idx_packages_project ON packages(project_id);
CREATE INDEX IF NOT EXISTS idx_packages_name ON packages(name);

-- Detected vulnerabilities in packages
CREATE TABLE IF NOT EXISTS vulnerabilities (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    package_id INTEGER NOT NULL REFERENCES packages(id) ON DELETE CASCADE,
    cve_id TEXT NOT NULL,
    severity TEXT,
    cvss_score REAL,
    summary TEXT,
    fix_version TEXT,
    detected_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    dismissed_at DATETIME,
    UNIQUE(package_id, cve_id)
);

-- Indexes for vulnerability queries
CREATE INDEX IF NOT EXISTS idx_vulns_package ON vulnerabilities(package_id);
CREATE INDEX IF NOT EXISTS idx_vulns_cve ON vulnerabilities(cve_id);
CREATE INDEX IF NOT EXISTS idx_vulns_severity ON vulnerabilities(severity);

-- Scan history
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    started_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    completed_at DATETIME,
    packages_scanned INTEGER DEFAULT 0,
    vulns_found INTEGER DEFAULT 0,
    status TEXT DEFAULT 'running'
);

-- Index for scan history by project
CREATE INDEX IF NOT EXISTS idx_scans_project ON scans(project_id);

-- Schema version tracking for migrations
CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER PRIMARY KEY,
    applied_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Insert initial schema version if not exists
INSERT OR IGNORE INTO schema_version (version) VALUES (1);
`

// currentSchemaVersion is the current database schema version.
// Increment this when adding migrations.
const currentSchemaVersion = 1

// migrations contains SQL statements for upgrading from version N to N+1.
// Key is the version being upgraded FROM.
var migrations = map[int]string{
	// Example migration from v1 to v2:
	// 1: `ALTER TABLE vulnerabilities ADD COLUMN aliases TEXT;`,
}
