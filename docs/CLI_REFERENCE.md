# OVRSE CLI Reference

The `ovrse` CLI provides tools for:

- **Scanning** projects for vulnerabilities
- **MCP server** for AI assistant integration
- **Planning** remediations from templates
- **Validating** OVRS templates and KB files

---

## Installation

```bash
# macOS/Linux
brew install emphereio/tap/ovrse

# Or with Go
go install github.com/emphereio/ovrse/cmd/ovrse@latest

# Or build from source
git clone https://github.com/emphereio/ovrse.git
cd ovrse
make build
./bin/ovrse --version
```

---

## Command: `scan`

Scan a project for vulnerabilities. Auto-detects ecosystem from lock files.

### Usage

```bash
ovrse scan [flags] PATH
```

### Flags

| Flag | Description |
|------|-------------|
| `--json` | Output results as JSON (for CI/CD pipelines) |
| `--ecosystem` | Force specific ecosystem (npm, pip, go) |

### Behavior

1. Walks the directory looking for lock files
2. Auto-detects ecosystem based on files found:
   - `package-lock.json` → npm
   - `requirements.txt` → pip
   - `go.sum` → go
3. Queries OSV for vulnerabilities affecting each package
4. Reports findings with vulnerability IDs

### Exit Codes

| Code | Meaning |
|------|---------|
| `0` | No vulnerabilities found |
| `1` | Vulnerabilities found, or runtime error |
| `2` | Invalid usage (bad flags, missing arguments) |

### Examples

```bash
# Scan current directory
ovrse scan .

# Scan specific project
ovrse scan ./my-node-project

# JSON output for CI/CD
ovrse scan --json ./my-project

# Force specific ecosystem
ovrse scan --ecosystem pip ./my-project
```

### Example Output

```
[npm] Scanned 2 packages
  [?] lodash@4.17.15 - GHSA-29mw-wpgm-hmr9
  [?] lodash@4.17.15 - GHSA-35jh-r3h4-6jhm
  [?] axios@0.21.0 - GHSA-4w2v-q235-vp99

Total: 2 packages, 3 vulnerabilities
```

### JSON Output Format

```json
[
  {
    "ecosystem": "npm",
    "packages_scanned": 2,
    "findings": [
      {
        "package": {
          "name": "lodash",
          "version": "4.17.15",
          "ecosystem": "npm",
          "source": "package-lock.json"
        },
        "vulnerabilities": [
          {
            "id": "GHSA-29mw-wpgm-hmr9",
            "severity": "HIGH",
            "summary": "Prototype pollution in lodash"
          }
        ]
      }
    ],
    "status": "success"
  }
]
```

---

## Command: `mcp`

Start the MCP (Model Context Protocol) server for AI assistant integration.

### Usage

```bash
ovrse mcp
```

### Behavior

Starts an MCP server that communicates over stdio. The server provides tools that AI assistants (Claude, Cursor, etc.) can use for vulnerability scanning and remediation.

### Available Tools

| Tool | Description |
|------|-------------|
| `scan_project` | Scan a directory for vulnerabilities |
| `list_ecosystems` | List available ecosystem plugins |
| `get_fix` | Get upgrade command for a package |
| `check_if_affected` | Check if a version is vulnerable |
| `analyze_cve` | Get full CVE analysis with fix commands |
| `get_cve_verdict` | Quick risk priority check |
| `batch_triage` | Triage multiple CVEs by risk |
| `report_remediation_outcome` | Report fix success/failure |

### Client Configuration

**Claude Desktop / Cursor:**

```json
{
  "mcpServers": {
    "ovrse": {
      "command": "ovrse",
      "args": ["mcp"]
    }
  }
}
```

**Remote MCP (hosted):**

```json
{
  "mcpServers": {
    "ovrse": {
      "url": "https://mcp.ovrse.dev"
    }
  }
}
```

### Example Prompts

Once connected, you can ask your AI assistant:

- *"Scan my project for vulnerabilities"*
- *"Is lodash 4.17.15 affected by any CVEs?"*
- *"What's the fix for CVE-2021-23337?"*
- *"Triage these CVEs by risk: CVE-2024-1234, CVE-2024-5678"*

---

## Command: `validate`

Validate OVRS templates and KB files for structural correctness.

### Usage

```bash
ovrse validate [--templates-dir PATH] [--kb-dir PATH]
```

### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--templates-dir` | `examples/templates` | Directory containing template YAML files |
| `--kb-dir` | `examples/kb` | Directory containing KB YAML files |

### Behavior

1. Recursively walks template and KB directories
2. Parses templates into `ovrs.Template` structures
3. Parses KB files into `CveMapping` or `PackageRelease` structures
4. Runs validation on each parsed object
5. Reports errors and exits non-zero if any validation fails

### Example

```bash
ovrse validate \
  --templates-dir examples/templates \
  --kb-dir examples/kb
```

---

## Command: `plan`

Create a remediation plan for a single CVE on a single host.

### Usage

```bash
ovrse plan \
  --cve CVE-ID \
  --os-family FAMILY \
  --distribution DISTRO \
  --release RELEASE \
  --arch ARCH \
  [--package NAME] [--version VERSION] \
  [--templates-dir PATH] [--kb-dir PATH] \
  [--output json|yaml] \
  [--rendered] \
  [--explain]
```

### Required Flags

| Flag | Description | Example |
|------|-------------|---------|
| `--cve` | CVE to plan for | `CVE-2025-1234` |
| `--os-family` | OS family | `debian`, `rhel` |
| `--distribution` | Distribution | `debian`, `ubuntu`, `centos` |
| `--release` | Release version | `12`, `22.04` |
| `--arch` | Architecture | `amd64`, `arm64` |

### Optional Flags

| Flag | Description |
|------|-------------|
| `--package` | Package name on the host |
| `--version` | Current package version |
| `--templates-dir` | Override templates directory |
| `--kb-dir` | Override KB directory |
| `--output` | Output format: `json` or `yaml` |
| `--rendered` | Include rendered steps in output |
| `--explain` | Human-readable summary instead of JSON |

### Example: JSON Output

```bash
ovrse plan \
  --cve CVE-2025-1234 \
  --os-family debian \
  --distribution debian \
  --release 12 \
  --arch amd64 \
  --package nginx \
  --version 1.22.0 \
  --rendered \
  --output json
```

### Example: Human Explanation

```bash
ovrse plan \
  --cve CVE-2025-1234 \
  --os-family debian \
  --distribution debian \
  --release 12 \
  --arch amd64 \
  --explain
```

Output:

```
Plan for CVE-2025-1234 on host host-1

  Template:        os.debian.package-upgrade.nginx
  Target package:  nginx
  Current version: 1.22.0
  Target version:  1.24.0

  CVEs that will be fixed by this upgrade:
    - CVE-2024-9999
    - CVE-2025-1234
    - CVE-2025-5678
```

---

## Command: `plan-host`

Plan actions for a host with multiple findings.

### Usage

```bash
ovrse plan-host \
  --host-file host.json \
  --findings-file findings.json \
  [--templates-dir PATH] [--kb-dir PATH] \
  [--output json|yaml] \
  [--explain]
```

### Required Flags

| Flag | Description |
|------|-------------|
| `--host-file` | JSON file describing the host |
| `--findings-file` | JSON array of findings |

### Input Format

**host.json:**

```json
{
  "id": "host-abc",
  "osFamily": "debian",
  "distribution": "debian",
  "release": "12",
  "architecture": "amd64",
  "packages": {
    "nginx": "1.22.0"
  }
}
```

**findings.json:**

```json
[
  {"cveId": "CVE-2025-1234", "packageName": "nginx"},
  {"cveId": "CVE-2025-5678", "packageName": "nginx"}
]
```

### Example

```bash
ovrse plan-host \
  --host-file host.json \
  --findings-file findings.json \
  --explain
```

Output:

```
Plan for host host-abc

  Total findings:      2
  Actions:             1
  Distinct CVEs fixed: 3

  Action 1:
    Template:        os.debian.package-upgrade.nginx
    Package:         nginx
    Current version: 1.22.0
    Target version:  1.24.0
    Fixed CVEs:
      - CVE-2024-9999
      - CVE-2025-1234
      - CVE-2025-5678
```

---

## Global Options

| Flag | Description |
|------|-------------|
| `--version` | Print version and exit |
| `--help` | Print help for any command |

---

## Code Structure

| Path | Description |
|------|-------------|
| `cmd/ovrse/main.go` | CLI entry point |
| `pkg/ecosystem/` | Ecosystem plugins (npm, pip, go) |
| `pkg/mcp/` | MCP server implementation |
| `pkg/ovrs/` | Template parser |
| `pkg/kb/` | Knowledge base loaders |
| `pkg/plan/` | Remediation planner |
| `pkg/render/` | Template renderer |

---

## Adding New Commands

To add a new command:

1. Add command handling in `cmd/ovrse/main.go`
2. Follow existing patterns for flag consistency
3. Use `--json` for machine-readable output
4. Use `--explain` for human-readable summaries
5. Exit `0` for success, non-zero for errors

Keep flag names consistent:
- `--templates-dir`, `--kb-dir` for paths
- `--output json|yaml` for format selection
- `--explain` for human-readable mode
