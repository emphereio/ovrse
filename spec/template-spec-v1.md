# OVRS Template Specification v1

> **Status:** This is the **normative v0.1 specification** for OVRS templates.
> Where this document differs from [`rfcs/RFC-0001-ovrs-core.md`](rfcs/RFC-0001-ovrs-core.md), this specification takes precedence for v0.1 implementation.
> RFC-0001 describes an extended model for future versions.

An **OVRS Template** is a reusable remediation pattern.

It answers the question:

> “Given an environment that matches these conditions, and parameters such as package and version, what are the safe steps, checks and rollbacks needed to move from vulnerable to fixed?”

Templates are:

- General enough to be reused across many assets and CVEs
- Specific enough for an engine to turn into concrete tasks
- The main unit of repeatability for automated and agentic systems

This document describes the v1 shape of a template.

## Top level fields

```yaml
id: "os.debian.package-upgrade.nginx"
version: "1.0.0"

summary: "Upgrade nginx on Debian based hosts to a safe version"
description: "Performs a controlled nginx upgrade with preflight checks, restart, and health validation."

metadata:
  owner: "emphere-core"
  visibility: "internal-global"  # internal-global | public | tenant-local
  maturity: "stable"             # draft | experimental | stable | deprecated
  tags: ["os", "nginx", "web", "package-upgrade"]
```

### `id`

A globally unique identifier for the template.

Recommended format:

* segments separated by dots
* from general to specific

Examples:

* `os.debian.package-upgrade`
* `os.debian.package-upgrade.nginx`
* `cloud.aws.s3.make-bucket-private`

### `version`

Semantic version of the template definition. Bump when:

* Steps change in a meaningful way
* Preconditions or validation change
* Rollback semantics change

### `summary` and `description`

Human readable text that explains what the template does. Shown in UIs and logs.

### `metadata`

Additional information about the template.

* `owner`
  Team or entity that maintains the template.

* `visibility`
  `public`
  Suitable for inclusion in the public OVRSE knowledge base.

  `internal-global`
  Used internally across customers in a multi-tenant platform.

  `tenant-local`
  Specific to a single tenant or environment.

* `maturity`
  `draft`
  Early sketch, not ready for broad use.

  `experimental`
  Used in a few environments, may change.

  `stable`
  Proven in production in multiple environments.

  `deprecated`
  Should not be used for new work.

* `tags`
  Free form labels for searching and grouping.

---

## Applicability and matching

The `match` block describes where a template is valid.

```yaml
match:
  resourceKinds: ["vm", "baremetal"]
  osFamilies: ["debian"]
  distributions: ["debian", "ubuntu"]
  osVersionRange: ">=10"
  requiredPackages:
    - name: "nginx"
  requiredCapabilities:
    - "os.package_install"
    - "os.service_restart"
```

These fields are used by planners to decide which templates can be considered for a given asset.

* `resourceKinds`
  High level resource types such as `vm`, `container`, `baremetal`.

* `osFamilies`
  Families like `debian`, `rhel`, `windows`.

* `distributions`
  Specific distributions within a family such as `debian`, `ubuntu`, `centos`, `rocky`.

* `osVersionRange`
  Version constraint for OS versions expressed in a consistent format. A planner is responsible for interpreting this (for example using semver style logic for numbered releases).

* `requiredPackages`
  A list of packages that must be present for this template to make sense. This is checked against inventory or SBOM.

* `requiredCapabilities`
  Capabilities that an execution engine must support to run this template. For example `os.package_install` or `cloud.aws.s3.set_public_access_block`.

If any of these constraints are not satisfied, a planner should not propose this template.

---

## Parameters

Templates use parameters to make them reusable.

```yaml
parameters:
  - name: "targetPackage"
    type: "string"
    required: true
    description: "Name of the package to upgrade"

  - name: "targetVersion"
    type: "string"
    required: true
    description: "Minimum version that is considered fixed"

  - name: "serviceName"
    type: "string"
    required: true
    description: "Service that should be restarted after upgrade"

  - name: "maintenanceWindow"
    type: "string"
    required: false
    description: "Optional window identifier or tag for scheduling"
```

Fields:

* `name`
  Parameter name.

* `type`
  Basic scalar types for v1: `string`, `number`, `boolean`. Lists or maps can be added in later revisions.

* `required`
  Whether this parameter must be supplied to instantiate a plan.

* `description`
  Human readable explanation for UIs and documentation.

Parameters are referenced elsewhere in the template using `{{ name }}` syntax.

---

## Preflight checks

Preflight checks validate that it makes sense to run the plan before any changes are made.

```yaml
preflight:
  - id: "check_package_installed"
    kind: "os.check_package"
    params:
      package: "{{ targetPackage }}"

  - id: "check_version_lt_target"
    kind: "os.check_version_less_than"
    params:
      package: "{{ targetPackage }}"
      version: "{{ targetVersion }}"

  - id: "check_service_exists"
    kind: "os.check_service"
    params:
      service: "{{ serviceName }}"
```

Each check has:

* `id`
  An identifier unique within this template.

* `kind`
  A capability name understood by the engine. For example `os.check_package` or `cloud.aws.s3.check_public`.

* `params`
  Parameters passed to the capability, which may reference template parameters.

Preflight checks must not make irreversible changes. Engines should treat them as read only operations.

If any required preflight check fails, the engine should not proceed to the main steps.

---

## Steps

The `steps` block describes the core remediation actions.

```yaml
steps:
  - id: "refresh_package_index"
    kind: "os.package_index_refresh"
    params: {}
    retryPolicy:
      maxAttempts: 3

  - id: "upgrade_package"
    kind: "os.package_install"
    dependsOn: ["refresh_package_index"]
    params:
      package: "{{ targetPackage }}"
      versionConstraint: ">= {{ targetVersion }}"

  - id: "restart_service"
    kind: "os.service_restart"
    dependsOn: ["upgrade_package"]
    params:
      service: "{{ serviceName }}"

  - id: "wait_for_port"
    kind: "os.wait_for_port"
    dependsOn: ["restart_service"]
    params:
      port: 80
      timeoutSeconds: 60
```

Step fields:

* `id`
  Identifier unique within the template.

* `kind`
  Capability name, similar to preflight.

* `dependsOn` (optional)
  List of step `id` values that must complete successfully before this step runs. This forms a directed acyclic graph.

* `params`
  Parameters for this step.

* `retryPolicy` (optional)
  Hints for how an engine may retry this step. v1 can support a simple `maxAttempts` and optional backoff.

Templates should describe the **minimal set of steps** needed for this pattern. Planners may still optimize across templates and assets to reduce duplicate work.

---

## Validation

Validation checks run after steps complete. They confirm that the intended outcome has been achieved and that the system is healthy.

```yaml
validation:
  - id: "check_package_at_or_above_target"
    kind: "os.check_version_greater_equal"
    params:
      package: "{{ targetPackage }}"
      version: "{{ targetVersion }}"

  - id: "http_health_check"
    kind: "http.check"
    params:
      url: "http://{{ inventory.hostname }}/"
      expectedStatus: 200
```

Fields are the same as preflight checks.

Engines can use validation results to decide:

* whether to mark the plan as successful
* whether to attempt rollback
* whether to request human review

---

## Rollback

Rollback describes what to do if the plan fails or is explicitly reverted.

```yaml
rollback:
  strategy: "package-downgrade"   # or snapshot | custom | none
  steps:
    - id: "downgrade_package"
      kind: "os.package_install"
      params:
        package: "{{ targetPackage }}"
        versionConstraint: "< {{ targetVersion }}"

    - id: "restart_service_rollback"
      kind: "os.service_restart"
      params:
        service: "{{ serviceName }}"
```

Fields:

* `strategy`
  High level hint, such as `snapshot`, `package-downgrade`, `custom` or `none`. Snapshot based rollbacks may be handled at the engine level rather than in this block.

* `steps`
  Steps that undo or mitigate the changes. Same structure as main steps.

If `rollback` is omitted, engines may rely solely on their own snapshotting or higher level policies.

---

## Remediation metadata and extensions

Templates can carry additional remediation specific metadata and implementation specific extensions.

```yaml
remediation:
  riskLevel: "medium"             # low | medium | high | critical
  requiresReboot: false
  typicalDurationSeconds: 180
  blastRadiusTags: ["web-tier"]
  changeType: "standard"          # standard | emergency

extensions:
  emphere.com/policyHints:
    disallowAutoRunInEnvironments: ["payment-prod"]
```

* `remediation`
  Hints that can be used by planners, UIs and policy engines.

* `extensions`
  Namespaced keys for implementation specific data. Consumers that do not understand a particular namespace should ignore it.

---

## Complete example

A complete example template is provided at:

* [`../examples/templates/os.debian.package-upgrade.nginx.yaml`](../examples/templates/os.debian.package-upgrade.nginx.yaml)

