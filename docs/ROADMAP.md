# OVRSE Roadmap

This document outlines the development roadmap for OVRSE.

---

## Current Status: v0.1 (Draft)

OVRSE is in early development. The core specification and reference implementation are functional but evolving.

### What's Working

- Core specification documents (template-spec-v1, kb-spec-v1, extensions-spec-v1)
- RemediationTemplate, CveMapping, and PackageRelease document types
- Extensions mechanism for attaching metadata to documents
- Working CLI with `validate`, `plan`, and `plan-host` commands
- Template rendering with parameter substitution
- Example templates and KB entries

### Known Limitations

- Limited content library (few templates and CVE mappings)
- No JSON Schema validation yet
- Basic version comparison logic
- No formal integration tests

---

## Near-Term Goals

### Content Library

- Expand template coverage:
  - Generic Debian/Ubuntu/RHEL package upgrade templates
  - Basic cloud remediation templates (AWS S3, Security Groups)
- Seed KB with real CVE mappings from public sources (OSV, vendor advisories)
- Add PackageRelease entries for common packages

### Validation & Testing

- Add JSON Schemas for all document types
- Integrate schema validation into loaders
- Add integration tests with fixtures and golden outputs
- Improve version comparison logic per ecosystem

### Documentation

- Integration guide for execution engines
- Contribution guidelines (CONTRIBUTING.md)
- More examples and tutorials

---

## Future Direction

### ExecutionPlan Format

Define a stable output format that execution engines can consume:
- Fully rendered steps with parameters resolved
- Preflight checks and validation criteria
- Metadata about CVEs fixed and provenance

### Ecosystem Growth

- CSAF ingestion tooling (parse advisories into OVRSE KB format)
- Community contribution workflow
- CI/CD for validating contributions

### Broader Coverage

- More OS families (Alpine, Windows, macOS)
- More cloud platforms (GCP, Azure)
- Application-level ecosystems (npm, pip, Maven, Go modules)

---

## How to Contribute

We welcome contributions in several areas:

1. **Templates**: Add remediation templates for new surfaces
2. **KB Entries**: Add CveMappings and PackageReleases for real CVEs
3. **Spec Improvements**: Propose clarifications or extensions to the spec
4. **Engine Development**: Improve the planner, validation, or CLI

See the main [README](../README.md) for contribution guidelines.

---

## Versioning

- **v0.x**: Active development, APIs may change
- **v1.0**: Stable spec and reference implementation (target: TBD)

We'll move to v1.0 once the spec is stable and has been validated by real-world usage.
