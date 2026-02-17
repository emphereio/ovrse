# OVRSE Roadmap

Development roadmap for OVRSE — the open remediation layer for vulnerability management.

---

## Current Status: v0.2 (Pre-release)

OVRSE is functional and actively used. The MCP server, CLI, and ecosystem plugins are production-ready for scanning and remediation intelligence workflows.

### What's Working

**Entry Points**
- MCP server with 8 tools for AI assistant integration (Claude, Cursor, Windsurf)
- Remote MCP at `https://mcp.emphere.dev/mcp/` (zero setup)
- Local MCP via `ovrse mcp` (privacy, offline)
- CLI with `scan`, `mcp`, `validate`, `plan`, `plan-host` commands

**Core Engine**
- Ecosystem plugins: npm, pip, Go modules
- Auto-detection from lock files (`package-lock.json`, `requirements.txt`, `go.sum`)
- OSV database queries for vulnerability data
- Intel API client with Ed25519 keypair authentication
- JWT token caching with automatic refresh

**Intelligence Layer**
- Pre-computed advisories for 6 ecosystems (npm, pypi, go, maven, cargo, gem)
- Risk prioritization (CISA KEV, EPSS, CVSS)
- Advisory sync every 4 hours

**OVRS Specification**
- RemediationTemplate, CveMapping, PackageRelease document types
- Extensions mechanism for metadata
- Template rendering with parameter substitution
- JSON schemas in `schema/` directory

### Known Limitations

- Limited template library (community contributions welcome)
- Basic version comparison logic (semver only)
- No formal integration test suite for CLI
- Intel API requires authentication for full features

---

## v0.3 Goals

### Ecosystem Expansion

- [ ] Maven plugin (`pom.xml`, `gradle.lockfile`)
- [ ] Cargo plugin (`Cargo.lock`)
- [ ] RubyGems plugin (`Gemfile.lock`)
- [ ] NuGet plugin (`packages.lock.json`)

### Template Library

- [ ] Generic Debian/Ubuntu package upgrade templates
- [ ] Generic RHEL/CentOS package upgrade templates
- [ ] Cloud remediation templates (AWS S3, Security Groups)
- [ ] Container image upgrade templates

### Testing & Validation

- [ ] CLI integration tests with fixtures
- [ ] MCP tool integration tests
- [ ] Golden output tests for plan generation
- [ ] CI validation for template contributions

### Documentation

- [ ] Integration guide for execution engines
- [ ] MCP tool cookbook with common workflows
- [ ] Template authoring guide

---

## v1.0 Criteria

OVRSE will move to v1.0 when:

1. **Spec Stability** — OVRS specification is frozen with backwards compatibility guarantees
2. **Ecosystem Coverage** — At least 6 ecosystem plugins (npm, pip, go, maven, cargo, gem)
3. **Template Library** — Templates for common OS families (Debian, RHEL, Alpine)
4. **Test Coverage** — >70% coverage across core packages
5. **Real-World Validation** — Used in production by multiple organizations
6. **Release Automation** — Binaries, container images, and package manager distribution

---

## Future Direction

### ExecutionPlan Format

Define a stable output format for execution engines:
- Fully rendered steps with parameters resolved
- Preflight checks and validation criteria
- Rollback procedures
- Metadata about CVEs fixed and provenance

### Plan & Apply Workflow

Terraform-style workflow for remediation:
- `ovrse plan` — Generate remediation plan (dry-run)
- `ovrse apply` — Execute remediation with confirmation
- `ovrse verify` — Validate fix was applied correctly

### Broader Platform Coverage

- More OS families (Alpine, Windows, macOS)
- Cloud platforms (AWS, GCP, Azure)
- Container orchestration (Kubernetes, ECS)
- Infrastructure as Code (Terraform, Pulumi)

### CSAF Integration

- Ingest CSAF advisories into OVRSE KB format
- Vendor advisory mapping
- Automated KB updates from upstream sources

---

## How to Contribute

1. **Ecosystem Plugins** — Add support for new package managers ([pkg/ecosystem/](../pkg/ecosystem/))
2. **Templates** — Add remediation templates ([examples/templates/](../examples/templates/))
3. **KB Entries** — Add CveMappings and PackageReleases ([examples/kb/](../examples/kb/))
4. **MCP Tools** — Propose new tools for AI workflows
5. **Documentation** — Improve guides and examples

See [CONTRIBUTING.md](../CONTRIBUTING.md) for guidelines.

---

## Versioning

| Version | Status | Commitment |
|---------|--------|------------|
| v0.x | Active development | APIs may change without notice |
| v1.0 | Stable | Backwards-compatible within major version |

We follow [Semantic Versioning](https://semver.org/). Breaking changes in v0.x are documented in [CHANGELOG.md](../CHANGELOG.md).
