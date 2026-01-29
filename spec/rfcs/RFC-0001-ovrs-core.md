# RFC-0001: OVRS Core Model & Document Types

**Title:** Open Vulnerability Remediation Specification (OVRS) – Core Model
**Status:** Draft
**Revision:** 0.1.0
**Authors:** Ankit Kumar
**Last Updated:** 2025-11-19

> **Note on Specification Hierarchy:**
> This RFC represents the **future direction** of OVRS/OVRSE and describes an extended model with additional features.
>
> **For v0.1 implementation**, the normative specifications are:
> - [`template-spec-v1.md`](../template-spec-v1.md) - Template structure and validation
> - [`kb-spec-v1.md`](../kb-spec-v1.md) - Knowledge base (CveMapping, PackageRelease)
>
> Where RFC-0001 differs from the v0.1 specs, **the v0.1 specs take precedence** for current implementation.
> This RFC serves as design documentation and a roadmap for future versions.

---

## 0. Purpose of this RFC

This document defines the *core model* and *document types* of the **Open Vulnerability Remediation Specification (OVRS)**.

It is intended for:

- Engineers implementing the reference engine (**OVRSE**)  
- Contributors authoring remediation templates and CVE mappings  
- Other vendors or tools evaluating OVRS as a remediation format

The goal is to be explicit, precise, and compatible with real-world vulnerability and package ecosystems (OS distributions, kernels, containers, cloud platforms), while keeping v0 scoped and tractable.

---

## 1. Problem Space

Today, most teams have:

- **Detection** through scanners:
  - Host and container scanners (Tenable, Qualys, Wiz, etc.)
  - SCA / dependency scanners (Snyk, Dependabot, etc.)
  - CSPM / cloud misconfiguration tools
- **Identification** through shared identifiers:
  - CVE IDs, NVD records, CISA KEV, vendor advisories
- **Tracking** through work management:
  - Jira, ServiceNow, spreadsheets, internal systems

What is missing is a **standard representation of remediation knowledge**:

- “For this CVE, on this OS/distribution, with this package/kernel/image version:
  - precisely what should I do to remediate it?
  - how safe is that change?
  - where does this remediation guidance come from?
  - which other CVEs will this change close?”

Today, that knowledge is expressed in:

- Free-form prose (advisories, wiki pages)
- Ad-hoc scripts
- Vendor-specific, non-portable formats

OVRS provides a structured, vendor-neutral format for remediation logic that:

- Can be validated, versioned, and reviewed
- Can be shared across tools and organizations
- Can be executed by different remediation engines

---

## 2. Scope of OVRS v0.1

### 2.1 In-scope

The initial version of OVRS focuses on:

1. **OS-level remediation**  
   - Package upgrades via system package managers:
     - Debian/Ubuntu (APT)
     - RHEL/CentOS/Alma/Rocky (YUM/DNF)
     - SUSE (Zypper)
   - Kernel updates modeled as packages where applicable
   - Basic OS configuration changes (e.g., SSH settings) as templated operations

2. **Cloud platform misconfiguration remediation** (at a minimal, illustrative level)  
   - AWS:
     - S3 bucket ACL / policy hardening
     - Security Group ingress fixes
   - GCP / Azure analogs (optional in v0.1)

3. **Application / dependency remediation** (minimal level)  
   - Bumping a package in `package.json` or `requirements.txt` and re-deploying

4. **Planning / recon only**  
   - OVRS v0.1 is **execution-agnostic**:
     - It describes *what* operations should be performed, under what assumptions.
     - It does not prescribe how a particular engine executes them.

### 2.2 Out-of-scope (for v0.1)

- Full-blown data models for:
  - All possible cloud resources
  - All language ecosystems
- Fine-grained kernels and driver-level operations beyond their representation as packages
- Detailed container image layering semantics
- Execution protocols (SSH, SSM, agents, etc.)
- Policy/prioritization logic (e.g. risk scoring, scheduling)

These may be addressed in follow-up RFCs.

### 2.3 Relationship to CSAF and other advisory formats

The Common Security Advisory Framework (CSAF) is an OASIS standard for machine-readable security advisories. CSAF documents are typically produced by vendors, CERTs, and coordinators, and describe:

- Affected products and versions (via `product_tree` and product status)
- Vulnerabilities (CVEs, scoring, references)
- High-level remediations and fixes (e.g., update to version X, apply patch Y)

OVRS is **not** an alternative to CSAF. Instead, it treats CSAF and similar advisory formats as **upstream data sources** and focuses on a different layer:

- CSAF answers: *"Which products/versions are affected and what vendor fixes exist?"*
- OVRS answers: *"On this specific host/container/cloud resource, what concrete operations, preflight checks, and validation steps should we perform to apply that fix safely?"*

Typical integration:

1. Ingest CSAF advisories from vendors / CISA.
2. Derive OVRS `PackageRelease` and `CveMapping` documents from the CSAF vulnerability and remediation sections.
3. Author or reuse OVRS `RemediationTemplate` documents that describe the concrete upgrade/configuration steps per OS, package manager, and resource type.

In other words, **CSAF describes advisories; OVRS describes executable plans.** They are complementary, not competing.

**Note:** CSAF is highlighted here as a primary example due to its structured, machine-readable format and authoritative sources (vendors, CERTs, CISA). However, OVRS is designed to work with any combination of advisory formats, scanner outputs, and software composition data.

---

## 3. Core Conceptual Model

### 3.1 Entities

OVRS deals primarily with the following conceptual entities:

- **CVE:** Vulnerability identifier (e.g., `CVE-2025-12345`).
- **Product:** A logical product or component name (e.g., `openssl`, `linux-kernel`, `git`).
- **OS Family:** A normalized base OS family (e.g., `debian`, `ubuntu`, `rhel`, `sles`, `windows`).
- **Distribution / Variant:** Concrete distribution within a family (e.g., `ubuntu-22.04`, `debian-12`).
- **Package:** A deployable unit managed by a package manager (e.g., `openssl`, `linux-image-5.15.0-91-generic`).
- **Kernel:** In many OSes, represented as a package (e.g., `linux-image-*`); treated as a package with special semantics.
- **Container Image:** An immutable artifact with an effective OS and package set; for OVRS v0.1 it is modeled via inferred OS family and installed packages.
- **Cloud Resource:** Named cloud objects with configuration state (e.g., `aws:s3:bucket`, `aws:ec2:security-group`).
- **Remediation Template:** A parameterized remediation pattern (recipe).
- **CveMapping:** A mapping from CVE to target-specific remediation templates and parameters.
- **PackageRelease:** A representation of a specific package version and the set of CVEs it fixes.

### 3.2 High-Level Flow

At a high level, OVRS describes the following flow:

1. **Input:**
   - Set of CVEs (from scanners or threat intel)
   - Inventory snapshot (hosts, OS, installed packages, container images, cloud resources)

2. **Lookup:**
   - For each CVE and environment:
     - Find applicable `CveMapping` entries.
     - Select the proper `RemediationTemplate` given OS family / resource type.
     - Bind template parameters (package name, fixed version, resource IDs, etc.).
     - Optionally consult `PackageRelease` to see which other CVEs will be addressed by the same fix.

3. **Plan:**
   - Instantiate the template into a **Remediation Plan** for each target.
   - Evaluate safety preflight conditions conceptually.
   - Attach provenance and expected CVE coverage.

4. **Execute (out-of-scope for OVRS, handled by engines):**
   - An external engine (e.g., OVRSE) uses the plan to perform actual changes.

OVRS standardizes everything up to the **Plan**.

---

## 4. Document Types

This section defines the core OVRS document types:

1. `RemediationTemplate`
2. `CveMapping`
3. `PackageRelease`

Each document MUST have:

- `apiVersion` – version of the OVRS API used (e.g., `ovrs.emphere.dev/v1alpha1`)
- `kind` – document type (`RemediationTemplate`, `CveMapping`, `PackageRelease`)

All examples use YAML, but JSON is permitted and structurally equivalent.

---

## 5. RemediationTemplate

### 5.1 Purpose

A **RemediationTemplate** is a reusable, parameterized remediation pattern. It describes:

- Where the template is applicable (OS families, resource types, etc.)
- Which parameters it requires
- The safety assumptions and provenance
- The planned sequence of steps
- How success can be validated

It is **CVE-agnostic**: it never includes hardcoded CVE IDs. CVE-specific context is provided by `CveMapping`.

### 5.2 Top-level structure

```yaml
apiVersion: ovrs.emphere.dev/v1alpha1
kind: RemediationTemplate

metadata:      # required
match:         # required
parameters:    # required
provenance:    # required
safety:        # required
plan:          # required
validation:    # optional but recommended
tests:         # optional but recommended

### 5.3 `metadata`

Describes identity, ownership, and high-level characteristics.

```yaml
metadata:
  id: os.debian.package-upgrade          # string, globally unique within OVRS template registry
  name: "Debian/Ubuntu package upgrade via apt"
  version: "0.1.0"                       # semver
  description: >
    Upgrade a single Debian/Ubuntu package to a vendor-specified minimum version
    using apt, typically to remediate one or more CVEs.

  owners:
    - team: "emphere-core"
      github: "emphereio"

  tags:
    - os
    - debian
    - package
    - upgrade

  maturity: experimental                 # enum: experimental | beta | stable

  createdAt: "2025-11-19T00:00:00Z"
  updatedAt: "2025-11-19T00:00:00Z"
```

**Rules:**

* `id` MUST be unique among templates.
* `version` SHOULD follow semantic versioning.
* `maturity` indicates production readiness of the *template*, not OVRS itself.

### 5.4 `match`

Defines the environments where this template is valid.

```yaml
match:
  osFamilies: ["debian", "ubuntu"]       # optional; empty means not OS-bound
  distributions: []                      # optional; e.g. ["ubuntu-22.04", "ubuntu-20.04"]
  packageManagers: ["apt"]               # optional
  resourceTypes: ["vm", "baremetal"]     # e.g. vm, container, pod, function, s3-bucket, security-group

  constraints:
    requiresRoot: true
    supportedArchitectures: ["amd64", "arm64"]
    notes: >
      Assumes vendor-supported Debian/Ubuntu security repositories are configured.
```

**Guidance:**

* Engines MUST ensure basic match compatibility (e.g., `osFamily` must match).
* Distributions are strings such as `ubuntu-22.04`, `debian-12`, `rhel-9`. Normalization rules should be documented separately (e.g., in `docs/os-normalization.md`).

### 5.5 `parameters`

Defines the input parameters for the template and their types.

```yaml
parameters:
  package:
    type: string
    description: "Name of the package to upgrade"
    required: true
    examples: ["openssl", "git"]

  minVersion:
    type: string
    description: "Minimum fixed version (format determined by package ecosystem)"
    required: true
    examples: ["2.43.7-1"]

  allowDowngrade:
    type: boolean
    description: "Permit downgrades if currently installed version is higher but vulnerable"
    required: false
    default: false

  rebootPolicy:
    type: string
    description: "Reboot behavior after patch"
    enum: ["never", "when_required", "always"]
    default: "when_required"
```

**Types:**

* `string`
* `boolean`
* `integer`
* `number`
* `enum` (via `enum` field)
* In future, structured types (array/object) MAY be introduced via separate RFC.

**Rules:**

* Implementations MUST validate that all required parameters are present and type-correct.
* String parameter semantics (e.g., version comparison) are determined by the **ecosystem** (APT, DNF, npm, etc.). Document these in per-ecosystem docs.

### 5.6 `provenance`

Captures where the remediation guidance comes from.

```yaml
provenance:
  fixType: vendor-pkg-manager            # enum: vendor-pkg-manager | vendor-patch | cloud-api | community-script
  sources:
    - type: csaf-advisory
      url: "https://example.com/security/csaf/vendor-2025-001.json"
      notes: "See vulnerability index 0 for CVE-2025-48384."
    - type: vendor-advisory
      url: "https://www.debian.org/security/2025/dsa-XXXX"
    - type: nvd
      url: "https://nvd.nist.gov/vuln/detail/CVE-2025-48384"
  notes: >
    This template assumes vendor-supported Debian/Ubuntu security repositories
    are configured and uses apt to install the vendor-provided fixed package version.
```

**Rules:**

* At least one `source` SHOULD be provided.
* `type` SHOULD be one of:
  - `csaf-advisory` – CSAF document or specific vulnerability entry
  - `vendor-advisory` – vendor security advisory (HTML/PDF)
  - `nvd` – NVD entry
  - `cisa-kev` – CISA KEV catalog entry
  - `community` – community research / write-up
  - `other` – anything else (documented in `notes`)
* `notes` SHOULD explain assumptions relevant to safety and correctness.

### 5.7 `safety`

Defines risk classification, preconditions, and rollback strategy.

```yaml
safety:
  changeScope: "package-upgrade"         # e.g. package-upgrade, kernel-upgrade, config-change, cloud-policy-change
  riskLevel: "medium"                    # enum: low | medium | high
  requiresReboot: "conditional"          # enum: never | conditional | always
  destructive: false                     # e.g. data-loss potential

  potentialSideEffects:
    - "Services provided by {{ package }} may be restarted."
    - "Minor behavior changes may occur between versions."

  preflightChecks:
    - id: "os-family"
      type: os_family_is
      params:
        expected: ["debian", "ubuntu"]

    - id: "package-installed"
      type: package_installed
      params:
        packageParam: "package"

    - id: "version-less-than-fixed"
      type: package_version_less_than
      params:
        packageParam: "package"
        versionParam: "minVersion"

  rollbackStrategy:
    type: "snapshot"                     # enum: snapshot | package-downgrade | manual | none
    notes: >
      Recommended to pair with VM or filesystem snapshots orchestrated by the execution engine.
```

**Notes:**

* `preflightChecks` are *declarative* checks that an engine MAY evaluate using its own inventory/inspection capabilities.
* `type` values for checks are opaque strings interpreted by the engine (e.g., `os_family_is`, `package_installed`).
* `rollbackStrategy` is guidance; it does not guarantee rollback behavior.

### 5.8 `plan`

The heart of the template: the planned steps.

```yaml
plan:
  summary: "Upgrade {{ package }} to at least {{ minVersion }} using apt on Debian/Ubuntu."
  rationale: >
    This updates {{ package }} to a vendor-provided version that fixes all known
    vulnerabilities covered by the associated advisories while remaining on the
    same major release line where possible.

  steps:
    - id: "update-index"
      title: "Refresh package index"
      description: "Run 'apt-get update' to refresh the package index."
      kind: "os.package_index_refresh"
      params: {}                         # optional

    - id: "select-version"
      title: "Ensure fixed version is available"
      description: >
        Query available versions of {{ package }} and ensure a version >= {{ minVersion }}
        is available from a trusted repository.
      kind: "os.package_version_resolve"
      params:
        minVersion: "{{ minVersion }}"

    - id: "apply-upgrade"
      title: "Install fixed package"
      description: >
        Install {{ package }} at a version >= {{ minVersion }} using apt. If the currently
        installed version is already >= {{ minVersion }}, no change is necessary.
      kind: "os.package_install"
      params:
        package: "{{ package }}"
        versionConstraint: ">= {{ minVersion }}"

    - id: "restart-services"
      title: "Restart affected services if necessary"
      description: >
        Restart systemd services that depend on {{ package }}, if any.
      kind: "os.service_restart"
      optional: true
```

**Fields:**

* `summary` – short description of the plan (with template interpolation).
* `rationale` – explanation of why this is the preferred remediation.
* `steps` – ordered list of step objects.

Each `step` MUST include:

* `id` – unique within the template.
* `title` – human-readable label.
* `description` – human-readable description.
* `kind` – canonical operation identifier (e.g., `os.package_install`, `cloud.aws.s3_set_policy`).

`params` is an arbitrary key/value map, with values typically strings that may include template expressions (`{{ ... }}`).

`kind` is interpreted by engines; OVRS does not standardize the full universe of `kind` values, but recommends a namespaced convention:

* `os.*` for OS-level operations
* `cloud.aws.*`, `cloud.gcp.*`, `cloud.azure.*` for cloud operations
* `app.node.*`, `app.python.*` for language-specific operations

### 5.9 `validation`

Defines conceptual success criteria for the remediation.

```yaml
validation:
  successCriteria:
    - id: "version-fixed"
      description: "Installed version of {{ package }} is >= {{ minVersion }}."
      kind: "os.package_version_check"
      params:
        packageParam: "package"
        minVersionParam: "minVersion"

    - id: "no-vuln-reported"
      description: "Scanner no longer reports associated CVEs on this host."
      kind: "external.scanner_check"
      optional: true
```

Engines MAY map these to concrete checks (commands, APIs). They SHOULD at least propagate them into human-readable plans.

### 5.10 `tests`

Optional self-tests to catch obvious template issues.

```yaml
tests:
  - name: "git_upgrade_debian"
    description: "Check that git upgrade plan is generated for an older version"
    fixture:
      osFamily: "debian"
      distribution: "debian-12"
      packages:
        git: "2.43.0-0"
    input:
      package: "git"
      minVersion: "2.43.7-1"
    expect:
      preflightPass: true
      generatedPlan:
        stepCount: 4
        containsSteps: ["update-index", "apply-upgrade"]
```

The OVRSE reference engine SHOULD provide a harness to run these tests as part of CI.

---

## 6. CveMapping

### 6.1 Purpose

A **CveMapping** document connects a single CVE to:

* A high-level summary (product, severity, references)
* One or more **targets**, each describing:

    * OS family and distribution (optionally)
    * Product/package identifiers
    * The **fixed version** (if applicable)
    * The `RemediationTemplate` to use
    * Parameter bindings for that template

This allows templates to remain generic while capturing per-CVE details externally.

### 6.2 Structure

```yaml
apiVersion: ovrs.emphere.dev/v1alpha1
kind: CveMapping

cve: "CVE-2025-48384"
product: "git"
summary: "Remote code execution in git"
severity: "critical"                     # string; semantics depend on source (CVSS/CVSSv3 etc.)

advisory:                                # optional: reference to upstream advisory document
  type: "csaf"
  id: "VENDOR-2025-0001"
  publisher: "Vendor Software"
  url: "https://example.com/security/csaf/VENDOR-2025-0001.json"
  vulnerabilityIndex: 0                  # optional: index into CSAF vulnerabilities[] array

references:
  - type: nvd
    url: "https://nvd.nist.gov/vuln/detail/CVE-2025-48384"
  - type: vendor-advisory
    url: "https://www.debian.org/security/2025/dsa-XXXX"

targets:
  - osFamily: "debian"
    distributions: ["debian-12", "ubuntu-22.04"]   # optional, more precise targeting
    package:
      name: "git"
      manager: "apt"
    fixedVersion: "2.43.7-1"
    template: "os.debian.package-upgrade"
    templateParameters:
      minVersion: "2.43.7-1"

  - osFamily: "rhel"
    distributions: ["rhel-8", "rhel-9"]
    package:
      name: "git"
      manager: "dnf"
    fixedVersion: "2.43.7-2"
    template: "os.rhel.package-upgrade"
    templateParameters:
      minVersion: "2.43.7-2"
```

**Notes:**

* A single `CveMapping` can have many `targets` to cover different OS families, distributions, and ecosystems.
* `fixedVersion` semantics depend on package manager (e.g., epoch:version-release for RPM/DEB).
* The optional `advisory` block MAY reference an upstream advisory document (e.g., CSAF, vendor HTML advisory). For CSAF, `id`, `publisher`, and `url` SHOULD correspond to the CSAF document metadata, and `vulnerabilityIndex` MAY point to the specific `vulnerabilities[]` entry in that document.

### 6.3 Kernel and containers

For kernel vulnerabilities:

* `package.name` MAY refer to kernel meta-packages (e.g., `linux-image-generic`, `kernel-rt`).
* Additional guidance (e.g., `changeScope: kernel-upgrade` in templates) SHOULD be used to mark higher risk.

For container images in v0.1:

* Mappings MAY still reference OS-family templates, relying on engines to:

    * Derive the effective OS family and packages for an image.
    * Decide how to apply the remediation (e.g., rebuild and redeploy image).

Future RFCs may define `image`-specific targets more explicitly.

---

## 7. PackageRelease

### 7.1 Purpose

A **PackageRelease** document represents a specific package build/version on a given OS family/distribution and the set of CVEs it fixes.

This allows engines to answer:

* “If we upgrade to this version, which CVEs will be remediated?”
* “After applying this plan, which CVEs can we mark as fixed?”

### 7.2 Structure

```yaml
apiVersion: ovrs.emphere.dev/v1alpha1
kind: PackageRelease

id: "debian:git:2.43.7-1"
osFamily: "debian"
distribution: "debian-12"
package:
  name: "git"
  manager: "apt"
version: "2.43.7-1"

vendorErrata: "DSA-XXXX-1"               # optional; advisory/errata ID

sourceAdvisories:                        # optional: upstream advisory documents
  - type: "csaf"
    id: "VENDOR-2025-0001"
    url: "https://example.com/security/csaf/VENDOR-2025-0001.json"
  - type: "vendor-advisory"
    id: "DSA-XXXX-1"
    url: "https://www.debian.org/security/2025/dsa-XXXX"

cvesFixed:
  - "CVE-2025-48384"
  - "CVE-2025-11111"
  - "CVE-2024-99999"
```

**Notes:**

* `id` SHOULD be a stable, unique key per OS+package+version.
* `cvesFixed` is the set of CVEs that this release is known to remediate for this OS/distribution.
* `sourceAdvisories` MAY list upstream advisory documents (CSAF, vendor bulletins, etc.) that assert this package release fixes the listed CVEs. For CSAF, `id` and `url` SHOULD align with the advisory metadata.
* Engines can join `CveMapping.targets[*].fixedVersion` to `PackageRelease.version` to derive additional CVEs that will be fixed by the same action.

---

## 8. Upstream Data Sources (CSAF, SBOM, scanner feeds)

OVRS does not define how vulnerability and product information is obtained. In practice, OVRSE and other implementations are expected to ingest data from:

- **CSAF advisories** published by vendors, CERTs, and CISA
- **Scanner outputs** (host/container scans, CSPM, SCA)
- **SBOM / VEX documents** describing software composition and exploitability

A typical flow is:

1. Parse CSAF documents to identify affected products, versions, and vendor remediations (e.g., minimum fixed version per product).
2. Normalize these into OVRS `PackageRelease` and `CveMapping` documents for specific OS families, distributions, and packages.
3. Combine that with environment inventory and OVRS `RemediationTemplate` content to generate per-asset remediation plans.

The exact ingestion and normalization logic is implementation-specific and out-of-scope for OVRS v0.1, but OVRS fields are designed to carry references back to CSAF and similar upstream documents (via `advisory` and `sourceAdvisories` fields).

---

## 9. Inventory Snapshot (Engine-side)

OVRS itself does not strictly define the inventory model, but for completeness this RFC suggests a minimal shape that OVRSE MAY support.

```yaml
hosts:
  - id: "prod-web-01"
    kind: "vm"
    osFamily: "debian"
    distribution: "debian-12"
    architecture: "amd64"
    kernelVersion: "5.15.0-91-generic"
    packages:
      git: "2.43.0-0"
      openssl: "1.1.1u-1"

containers:
  - id: "frontend-1"
    image: "ghcr.io/example/frontend:sha256:..."
    effectiveOsFamily: "debian"
    packages:
      openssl: "1.1.1u-1"

cloudResources:
  - id: "arn:aws:s3:::my-bucket"
    kind: "aws:s3:bucket"
    region: "us-west-2"
    config:
      publicAccessBlock: false
      policyJson: "{...}"
```

Engines use:

* `osFamily`, `distribution`, `packages`, etc. to evaluate `match` and `preflightChecks`.
* CVEs coupled with these inventory items to select `CveMapping.targets`.

OVRS does **not** standardize these fields in v0.1, but templates and checks SHOULD be written with this shape in mind.

---

## 10. Resolution Algorithm (Informal)

This section describes an informal algorithm for going from **CVE + inventory** to **Remediation Plans**.

Given:

* A set of `CveMapping` documents
* A set of `RemediationTemplate` documents
* A set of `PackageRelease` documents
* An inventory snapshot

For each CVE `c` and each target asset `a` in inventory:

1. **Select relevant mappings**
   Find all `CveMapping` documents where `cve == c`. For each mapping:

    * For each `target` in `mapping.targets`:

        * If `target.osFamily` matches `a.osFamily`
        * And (if specified) `target.distributions` contains `a.distribution`
        * Then consider this `target` applicable to `a`.

2. **Check template match**
   For each applicable `target`:

    * Look up `RemediationTemplate` `T` where `metadata.id == target.template`.
    * Ensure `a` satisfies `T.match` (osFamily, resourceTypes, etc.).
    * If not, discard this target for this asset.

3. **Bind parameters**
   For each surviving `T`:

    * Create a parameter map `P`:

        * Start with `target.templateParameters`.
        * Optionally supplement with values derived from `a` and mapping (e.g., `package` from `target.package.name`).
    * Validate `P` against `T.parameters`.

4. **Evaluate preflight (conceptual)**

    * Evaluate `T.safety.preflightChecks` against `a` and `P` where possible.
    * Record pass/fail/unknown per check.

5. **Instantiate plan**

    * Apply `P` to `T.plan` and `T.validation` (template interpolation).
    * Produce a **Remediation Plan** object (engine-internal) containing:

        * Resolved steps
        * Safety metadata
        * Provenance metadata
        * Bound CVE `c`
        * Associated `PackageRelease` (if found for `fixedVersion`)

6. **Compute additional CVEs (optional but recommended)**
   If `PackageRelease` documents are present:

    * For each target’s `fixedVersion`, find matching `PackageRelease` docs:

        * `osFamily` == `a.osFamily`
        * `distribution` == `a.distribution` (if set)
        * `package.name` and `version` match
    * Attach `cvesFixed` to the plan for reporting (i.e., “this plan will remediate CVEs X, Y, Z”).

The result is a set of plans that can be displayed, exported, or passed to an execution engine.

---

## 11. Versioning and Compatibility

* Each document MUST specify `apiVersion`, e.g. `ovrs.emphere.dev/v1alpha1`.
* Minor backwards-compatible changes:

    * MAY add new optional fields.
    * MUST NOT change the meaning of existing required fields.
* Breaking changes:

    * MUST result in a new API version, e.g. `ovrs.emphere.dev/v1beta1` or `ovrs.emphere.dev/v2`.
    * SHOULD be accompanied by migration notes.

`RemediationTemplate.metadata.version` (semver) reflects changes in template content, independent of OVRS API version.

---

## 12. Security Considerations

* OVRS documents are **descriptive**, but engines that execute plans based on them are security-sensitive.
* Engines SHOULD:

    * Treat templates and mappings as untrusted until validated and curated.
    * Implement robust sandboxing, validation, and rollback for any execution layer.
    * Respect `safety` metadata and surface it to users (riskLevel, changeScope, requiresReboot, etc.).
* Authors SHOULD:

    * Avoid embedding arbitrary code or unbounded expressions in templates.
    * Provide accurate `provenance` and keep references up to date.

---

## 13. Open Questions / Areas for Feedback

This RFC is meant to be reviewed and iterated on. Specific areas where feedback is welcome:

1. **OS and distribution normalization**

    * Are `osFamilies` and `distribution` fields sufficient?
    * Do we need a more formal catalog of OS identifiers?

2. **Version comparison semantics**

    * Should OVRS standardize version comparison behavior per ecosystem (DEB, RPM, npm, etc.), or defer to engines?

3. **Container-specific modeling**

    * For v0.1, treating containers as “hosts with an OS + packages” is convenient but lossy.
    * Should OVRS define explicit `ContainerRelease` or `ImageRelease` documents?

4. **Cloud resource modeling**

    * Where should OVRS draw the line between remediation templates and a generalized cloud resource schema?
    * Does it make sense to define a minimal common schema for common resource families?

5. **Validation semantics**

    * Should OVRS standardize a minimal set of `validation.kind` operations, or leave them entirely engine-defined?

---

## 14. Glossary

* **OVRS:** Open Vulnerability Remediation Specification – the format described in this document.
* **OVRSE:** Reference engine/project implementing OVRS, plus official content.
* **Template:** `RemediationTemplate` – a parameterized remediation pattern.
* **Mapping:** `CveMapping` – a CVE-specific mapping to templates and parameters.
* **PackageRelease:** Document describing a specific OS/package version and the CVEs it fixes.
* **Inventory:** Representation of assets (hosts, containers, cloud resources) subject to remediation.
* **Engine:** Any system that consumes OVRS content and produces/executes remediation plans.
