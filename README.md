# OVRSE

<div align="center">
  <img src="assets/mascot/overseer.png" alt="The Overseer" width="200"/>
</div>

**OVRSE** (pronounced "oversee") is the open-source reference engine and content library for the **Open Vulnerability Remediation Specification (OVRS)**.

OVRS is a format for describing how to fix vulnerabilities, not just how to find them.
OVRSE is the project that makes that format real: templates, mappings, tools, and the Overseer keeping watch.

---

## Why this exists

Most of the industry is very good at one half of the problem:

- We can **find** vulnerabilities (Tenable, Wiz, Snyk, cloud-native scanners, SCA, CSPM…)
- We can **name** them (CVE, NVD, CISA KEV, vendor advisories)
- We can **track** them (Jira, ServiceNow, spreadsheets, internal tools)

But when someone asks a simple question:

> “Okay, for *this* CVE, on *this* system,  
> what exactly should we do to fix it, how safe is that change, and what else will it fix?”

…the real answer usually lives in:

- A wiki page that’s out of date  
- A one-off script in a random repo  
- Someone’s personal memory  
- Scanner-specific “fix” text that isn’t reusable

OVRSE and OVRS exist to give that answer a **shared, portable shape**.

---

## What is OVRS?

**OVRS (Open Vulnerability Remediation Specification)** is a vendor-neutral format for:

1. **Remediation templates**  
   Parameterised “recipes” for classes of fixes, for example:

   - Upgrade a Debian package to a vendor-fixed version via `apt`
   - Make an AWS S3 bucket private
   - Tighten a security group’s ingress rules
   - Bump an npm dependency to a safe version

2. **CVE mappings**  
   Documents that say:

   > “For CVE-2025-XXXX on OS family Y and package Z,  
   > use template T with these parameters.”

3. **Package releases**
   Documents that capture:

   > "This specific package version on this OS fixes CVEs A, B, and C
   > and corresponds to vendor advisory D."

4. **Extensions**
   Namespaced metadata that tools can attach to documents:

   > "For this CVE, here's the EPSS score, breaking change analysis,
   > stability assessment, and recommended verdict."

   See [`extensions-spec-v1.md`](./spec/extensions-spec-v1.md) for the `emphere.dev/intel` extension.

OVRS is designed to be:

- **Execution-agnostic** – it describes *what* to do and *under what assumptions*, not how a particular engine runs it.
- **Safety-aware** – safety, provenance, and verification guidance are first-class fields, not comments in a script.
- **Composable** – templates are generic; mappings and package data carry the per-CVE details.

The full OVRS spec lives in [`spec/SPEC.md`](./spec/SPEC.md).

### How does OVRS relate to CSAF?

CSAF (Common Security Advisory Framework) is a standard for machine-readable security advisories: vendors and coordinators publish JSON documents that say which products and versions are affected by which CVEs, and what vendor fixes exist.

OVRS does not try to replace CSAF.

Instead, OVRS assumes that advisories and scanner data (including CSAF) are upstream inputs. OVRS is focused on a different layer:

- **CSAF:** *"Product X, versions A–B are affected; update to version C."*
- **OVRS:** *"On this specific Debian 12 VM or AWS resource, here are the exact steps, preflight checks, and validation to apply that fix safely."*

OVRSE can ingest and synthesize data from multiple sources including CSAF advisories, scanner outputs, and SBOM/VEX documents, normalize them into `CveMapping` and `PackageRelease` documents, and then generate concrete remediation plans per asset using `RemediationTemplate` content.

---

## What is OVRSE?

**OVRSE** is the reference implementation of OVRS.

The project aims to provide:

- A **loader and validator** for OVRS documents:
  - `RemediationTemplate`
  - `CveMapping`
  - `PackageRelease`
- A **planner** for “recon mode”:
  - Take one or more CVEs and an inventory (hosts, OS, packages, cloud resources)
  - Resolve which templates apply where
  - Produce detailed remediation plans with safety and provenance attached
- A **growing library of official templates and mappings**:
  - OS-level (Debian, RHEL, Windows…)
  - Cloud-level (AWS, GCP, Azure…)
  - Application-level (Node, Python, etc.)

OVRSE is intentionally *not* a full-blown remediation platform.
It focuses on the **language and content** of remediation: the part everybody needs but most teams recreate privately.

**Why open source?** The remediation knowledge layer (templates, mappings, KB) benefits from being open and community-driven. Any execution engine can sit on top of OVRS/OVRSE and handle the heavy lifting of execution, snapshots, rollouts, and audits.

---

## Documentation

- [Project overview](docs/OVRSE_OVERVIEW.md)
- [Architecture and reference model](spec/ovrs-architecture.md)
- [CLI reference](docs/CLI_REFERENCE.md)
- [Development roadmap](docs/ROADMAP.md)

---

## How the pieces fit together

At a high level:

1. A scanner or inventory system tells you:
   - “Host `prod-web-01` is Debian, with `git` at version `2.43.0-0`”
   - “These CVEs are affecting it”

2. OVRSE uses OVRS content to answer:
   - “For CVE-2025-48384, on Debian, the fix is to upgrade `git` to at least `2.43.7-1`”
   - “That remediation uses the `os.debian.package-upgrade` template”
   - “Here is the step-by-step plan, the safety assumptions, and where the guidance came from”

3. An execution engine (Emphere, your own tooling, or something else) can then:
   - Take that plan
   - Apply it safely in your environment
   - Record what happened for audit and learning

OVRSE focuses on step 2: **turning “we found something” into “here’s a clear, structured plan to fix it.”**

---

## A quick look at a template

A simplified example of an OVRS `RemediationTemplate` for Debian package upgrades:

```yaml
apiVersion: ovrs.emphere.dev/v1
kind: RemediationTemplate

metadata:
  id: os.debian.package-upgrade
  name: "Debian/Ubuntu package upgrade via apt"
  version: "0.1.0"
  description: >
    Upgrade a single Debian/Ubuntu package to a vendor-specified minimum version
    using apt, typically to remediate one or more CVEs.
  tags: ["os", "debian", "package", "upgrade"]
  maturity: experimental

match:
  osFamilies: ["debian", "ubuntu"]
  packageManagers: ["apt"]
  resourceTypes: ["vm", "baremetal"]

parameters:
  package:
    type: string
    required: true
  minVersion:
    type: string
    required: true

provenance:
  fixType: vendor-pkg-manager
  sources:
    - type: vendor-advisory
      url: "https://www.debian.org/security/2025/dsa-XXXX"

safety:
  changeScope: "package-upgrade"
  riskLevel: "medium"
  requiresReboot: "conditional"
  preflightChecks:
    - id: "os-family"
      type: os_family_is
      expected: ["debian", "ubuntu"]
    - id: "package-installed"
      type: package_installed
      params:
        packageParam: "package"

plan:
  summary: "Upgrade {{ package }} to at least {{ minVersion }} using apt."
  steps:
    - id: "update-index"
      title: "Refresh package index"
      description: "Run 'apt-get update' to refresh the package index."
      kind: "os.package_index_refresh"
    - id: "apply-upgrade"
      title: "Install fixed package"
      description: "Install {{ package }} with a version constraint >= {{ minVersion }}."
      kind: "os.package_install"
      params:
        versionConstraint: ">= {{ minVersion }}"
```
Templates stay generic.
CVE-specific details live in `CveMapping` documents.
Package-to-CVE relationships live in `PackageRelease` documents.

---

## Project status

OVRSE is in its early days (v0.1 draft).

**Current state:**

* ✅ Core specification documents (template-spec-v1, kb-spec-v1, extensions-spec-v1)
* ✅ Extensions mechanism for attaching intelligence to CveMappings
* ✅ PackageRelease with dependency graph support
* ✅ Working CLI with validate, plan, and plan-host commands
* ✅ Functional planner with template rendering
* ✅ Example templates and KB entries

**Next priorities** (see [ROADMAP.md](docs/ROADMAP.md) for details):

* Build content library (more templates and CVE mappings)
* Add JSON schemas and integration tests
* Improve version comparison logic
* Create integration guide for execution engines

Expect the schema and APIs to move around a bit while we're still on `0.x`.
Once things feel solid and a few people are using OVRS in anger, we'll tighten the versioning story.

---

## Repository Layout

```text
ovrse/
  cmd/           # CLI entry point
    ovrse/         - Main CLI binary

  pkg/           # Go library packages
    ovrs/          - Template loading and validation
    kb/            - Knowledge base (CveMapping, PackageRelease)
    plan/          - Planning engine
    render/        - Template rendering
    inventory/     - Host inventory model

  spec/          # OVRS specification documents
    rfcs/          - RFCs (design documents, future direction)
    *.md           - Normative v0.1 specs (template-spec, kb-spec)

  examples/      # Example templates and KB for testing/docs
    templates/     - Example remediation templates
    kb/            - Example CVE mappings and package releases

  docs/          # Project documentation
    *.md           - Guides, architecture, roadmap

  content/       # Official curated templates and KB (WIP)
  schema/        # JSON Schemas for validation (WIP)
  tests/         # Integration tests and fixtures (WIP)
  assets/        # Mascot art, logos
```

**Key mental model:**
- `spec/` = OVRS specification (the standard)
- `cmd/` + `pkg/` = OVRSE reference implementation
- `examples/` = Working examples for v0.1
- `content/` = Future curated library (to be populated in Sprint 1)

---

## Contributing

If you care about the “fix” side of vulnerability management, you’re welcome here.

Ways to help:

* Propose changes or clarifications to the **OVRS spec** (`spec/SPEC.md`)
* Add or improve **remediation templates** under `content/templates/`
* Add **CVE mappings** and **package-release** documents
* Hack on the **engine**:

    * Better validation
    * Better planning logic
    * Inventory adapters

We’ll add a proper `CONTRIBUTING.md` as things settle.
In the meantime, opening an issue to discuss an idea before sending a large PR is very much appreciated.

---

## License

OVRSE is released under the **Apache 2.0** license.
See [`LICENSE`](./LICENSE) for the full text.
