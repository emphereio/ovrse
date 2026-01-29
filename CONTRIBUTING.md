# Contributing to OVRSE

Thank you for your interest in contributing to OVRSE (Open Vulnerability Remediation Specification & Engine).

## Ways to Contribute

### 1. Remediation Templates

Add templates for new remediation patterns:

- OS package upgrades (Debian, RHEL, Alpine, etc.)
- Cloud resource hardening (AWS, GCP, Azure)
- Application-level fixes (npm, pip, Maven, etc.)

Templates live in `examples/templates/` and follow the [template-spec-v1](spec/template-spec-v1.md).

### 2. Knowledge Base Entries

Add CVE mappings and package release data:

- `CveMapping`: Links CVEs to remediation templates
- `PackageRelease`: Documents which versions fix which CVEs

KB entries live in `examples/kb/` and follow the [kb-spec-v1](spec/kb-spec-v1.md).

### 3. Specification Improvements

Propose clarifications or extensions to the spec. For significant changes, open an issue first to discuss.

### 4. Reference Implementation

Improve the CLI, planner, or validation logic in the `pkg/` and `cmd/` directories.

## Development Setup

```bash
# Clone the repository
git clone https://github.com/emphereio/ovrse.git
cd ovrse

# Build
go build ./cmd/ovrse

# Run tests
go test ./...

# Validate a template
./ovrse validate examples/templates/os.debian.package-upgrade.nginx.yaml
```

## Pull Request Process

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-contribution`)
3. Make your changes
4. Run tests (`go test ./...`)
5. Commit with a clear message
6. Push and open a pull request

## Commit Messages

Use clear, descriptive commit messages:

```
feat: add RHEL package upgrade template
fix: correct version comparison for semver
docs: clarify CveMapping applicability fields
spec: add restartType field to safety schema
```

## Code Style

- Go code follows standard `gofmt` formatting
- YAML follows 2-space indentation
- Spec documents use consistent heading levels and field tables

## Questions?

- Open a [Discussion](https://github.com/emphereio/ovrse/discussions) for questions
- Open an [Issue](https://github.com/emphereio/ovrse/issues) for bugs or feature requests

## License

By contributing, you agree that your contributions will be licensed under the Apache 2.0 License.
