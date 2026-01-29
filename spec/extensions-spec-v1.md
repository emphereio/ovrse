# OVRSE Extensions Specification v1

> **Status:** Normative specification for OVRSE extension namespaces.

OVRSE documents support namespaced extensions that enable tools to attach additional metadata without modifying the core specification. This document defines the extension mechanism and registered namespaces.

---

## Extension Mechanism

Extensions are stored in the `extensions` field as a map of namespace to extension data:

```yaml
extensions:
  namespace.example/feature:
    field1: "value"
    field2: 123
```

### Namespace Format

Namespaces use reverse domain notation with a path component:
- `emphere.dev/intel` - Emphere intelligence extensions
- `vendor.example/custom` - Vendor-specific extensions

### Consumer Behavior

Implementations MUST:
- Preserve unknown extension namespaces when reading and writing documents
- Ignore extension namespaces they do not understand
- Handle missing extensions gracefully (extensions are OPTIONAL)

Implementations MAY:
- Validate extension data against registered schemas
- Surface extension data in user interfaces
- Fall back to default behavior when extensions are not present

### Distribution Note

Extensions may not be present in all distributions of OVRSE documents:

| Distribution | Extensions Present | Reason |
|--------------|-------------------|--------|
| Registry API | Yes | Full documents served |
| Git repository | No | Core-only export for open contribution |
| Offline/local | No | Uses Git clone |

Tools SHOULD NOT require extensions to function. If `extensions.emphere.dev/intel` is missing, use default prioritization (e.g., CVSS score alone) instead of failing.

---

## Registered Namespaces

| Namespace | Description | Specification |
|-----------|-------------|---------------|
| `emphere.dev/intel` | CVE intelligence from Emphere | This document |

---

## `emphere.dev/intel` Extension

The `emphere.dev/intel` extension provides CVE intelligence analysis from Emphere. It answers four critical questions:

1. **Should I patch?** - Urgency based on EPSS, CISA KEV, and exploitability
2. **Will it break?** - Breaking change detection and migration guidance
3. **Is it stable?** - Regret Index from post-release issue analysis
4. **What's the hidden cost?** - Transitive shadow (Fix 3, inherit 47)

### Schema

```yaml
extensions:
  emphere.dev/intel:
    # === VERDICT ===
    verdict: "patch_immediately"        # Required
    verdictReasoning: "string"          # Required
    confidence: 0.95                    # Required (0.0-1.0)

    # === URGENCY ===
    urgency:
      epssScore: 0.87                   # EPSS probability (0.0-1.0)
      epssPercentile: 0.99              # EPSS percentile (0.0-1.0)
      kevListed: true                   # In CISA KEV catalog
      kevDateAdded: "2024-03-29"        # Date added to KEV
      kevDueDate: "2024-04-19"          # Federal remediation deadline
      ransomwareUse: "Known"            # Known | Unknown | null
      cvssScore: 9.8                    # CVSS base score
      cvssVersion: "3.1"                # CVSS version used
      cvssSeverity: "CRITICAL"          # CRITICAL | HIGH | MEDIUM | LOW
      recommendedSla: "immediate"       # immediate | 7_days | 14_days | 30_days | opportunistic
      urgencyFactors:                   # Human-readable factors
        - "Listed in CISA KEV catalog"
        - "Known ransomware attack vector"

    # === SAFETY (Breaking Changes) ===
    safety:
      breakingSeverity: "minor"         # none | minor | major | critical
      breakingChanges:                  # List of breaking changes
        - type: "api_removal"
          description: "Removed deprecated API X"
          impact: "Applications using X will fail"
          workaround: "Use new API Y instead"
      regretIndex: 0.15                 # Likelihood of regretting upgrade (0.0-1.0)
      stabilityLevel: "stable"          # stable | caution | unstable | unknown
      requiresRestart: true             # Whether restart is needed
      restartType: "service"            # none | process | service | reboot
      restartReason: "Shared library updated"

    # === TRANSITIVE SHADOW ===
    transitive:
      cvesFixed: 3                      # CVEs fixed by this upgrade
      cvesInherited: 1                  # CVEs from new dependencies
      cvesResidual: 0                   # CVEs in fix version itself
      netChange: -2                     # Net CVE change (negative = improvement)
      recommendation: "proceed"         # proceed | proceed_with_caution | upgrade_further | block

    # === RENDERED STEPS ===
    renderedSteps:                      # Concrete remediation commands
      - order: 1
        action: "Update package to patched version"
        stepType: "command"             # instruction | command | verification
        command: "npm update lodash@4.17.21"
        category: "dependency_update"
        effort: "low"
      - order: 2
        action: "Run test suite"
        stepType: "verification"
        command: "npm test"
        category: "testing"
        effort: "low"

    # === ENVIRONMENT CONTEXT ===
    environment:
      appliesTo: "Node.js applications using lodash"
      doesNotApplyTo: "Applications not using affected functions"
      containerRelated: false
      kernelLevel: false

    # === SOURCES ===
    sources:
      - kind: "nvd"
        url: "https://nvd.nist.gov/vuln/detail/CVE-2024-1234"
      - kind: "osv"
        url: "https://osv.dev/vulnerability/CVE-2024-1234"
      - kind: "github_release"
        url: "https://github.com/lodash/lodash/releases/tag/4.17.21"

    # === SUMMARIES ===
    executiveSummary: "Critical vulnerability, patch immediately"
    engineerSummary: "Update lodash to 4.17.21, no breaking changes expected"

    # === CAVEATS ===
    caveats:
      - "Analysis based on publicly available data"

    # === TIMESTAMPS ===
    generatedAt: "2025-01-28T12:00:00Z"
    expiresAt: "2025-02-04T12:00:00Z"
```

### Field Reference

#### Verdict Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `verdict` | enum | Yes | Remediation decision |
| `verdictReasoning` | string | Yes | Explanation for the verdict |
| `confidence` | number | Yes | Confidence in analysis (0.0-1.0) |

**Verdict values:**
- `patch_immediately` - Critical risk, patch within 24-48 hours
- `patch_with_caution` - Safe to patch but mind breaking changes/stability
- `defer` - Low risk, can wait for scheduled maintenance
- `avoid` - Don't upgrade now, issues outweigh benefits
- `needs_review` - Conflicting signals, human review required
- `no_fix_available` - No patched version exists

#### Urgency Fields

| Field | Type | Description |
|-------|------|-------------|
| `epssScore` | number | EPSS probability of exploitation in next 30 days (0.0-1.0) |
| `epssPercentile` | number | EPSS ranking percentile (0.0-1.0) |
| `kevListed` | boolean | Whether CVE is in CISA Known Exploited Vulnerabilities catalog |
| `kevDateAdded` | string | Date CVE was added to KEV (ISO 8601 date) |
| `kevDueDate` | string | Federal remediation deadline from KEV |
| `ransomwareUse` | string | Known ransomware use: `Known`, `Unknown`, or null |
| `cvssScore` | number | CVSS base score |
| `cvssVersion` | string | CVSS version: `4.0`, `3.1`, `3.0`, `2.0` |
| `cvssSeverity` | string | CVSS severity: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW` |
| `recommendedSla` | string | Recommended remediation timeline |
| `urgencyFactors` | string[] | Human-readable list of urgency drivers |

**Recommended SLA values:**
- `immediate` - Within 24-48 hours (KEV, ransomware)
- `7_days` - Within 7 days (high EPSS, critical CVSS)
- `14_days` - Within 14 days (medium risk)
- `30_days` - Within 30 days (low risk)
- `opportunistic` - No SLA, patch when convenient

#### Safety Fields

| Field | Type | Description |
|-------|------|-------------|
| `breakingSeverity` | string | Breaking change severity: `none`, `minor`, `major`, `critical` |
| `breakingChanges` | array | List of breaking change objects |
| `regretIndex` | number | Likelihood of regretting upgrade (0.0-1.0) |
| `stabilityLevel` | string | Stability assessment: `stable`, `caution`, `unstable`, `unknown` |
| `requiresRestart` | boolean | Whether restart is needed for fix to take effect |
| `restartType` | string | Type of restart: `none`, `process`, `service`, `reboot` |
| `restartReason` | string | Why restart is required |

**Breaking change object:**
```yaml
type: "api_removal"           # api_removal | behavior_change | config_change | dependency | deprecation
description: "string"
impact: "string"
workaround: "string"          # Optional
reference: "url"              # Optional
```

#### Transitive Shadow Fields

| Field | Type | Description |
|-------|------|-------------|
| `cvesFixed` | integer | Number of CVEs fixed by this upgrade |
| `cvesInherited` | integer | CVEs introduced via new transitive dependencies |
| `cvesResidual` | integer | CVEs remaining in the fix version itself |
| `netChange` | integer | Net CVE change (negative = improvement) |
| `recommendation` | string | `proceed`, `proceed_with_caution`, `upgrade_further`, `block` |

#### Rendered Steps

Rendered steps are concrete remediation commands ready for execution or display.

| Field | Type | Description |
|-------|------|-------------|
| `order` | integer | Step order (1-based) |
| `action` | string | Human-readable action description |
| `stepType` | string | `instruction`, `command`, `verification` |
| `command` | string | Executable command (for command/verification types) |
| `alternatives` | array | Alternative commands for different platforms |
| `category` | string | Step category |
| `effort` | string | Estimated effort: `trivial`, `low`, `medium`, `high` |
| `notes` | string | Additional notes |

**Step types:**
- `instruction` - Human guidance that cannot be automated
- `command` - Executable terminal command (copy-paste ready)
- `verification` - Self-verifying command with PASS/FAIL output

**Alternative command object:**
```yaml
alternatives:
  - label: "Debian/Ubuntu"
    command: "apt update && apt upgrade nginx"
  - label: "RHEL/CentOS"
    command: "yum update nginx"
```

#### Environment Context

| Field | Type | Description |
|-------|------|-------------|
| `appliesTo` | string | Human-readable description of affected environments |
| `doesNotApplyTo` | string | Environments NOT affected |
| `containerRelated` | boolean | Whether CVE affects container runtimes |
| `kernelLevel` | boolean | Whether CVE affects kernel (impacts all containers on host) |

#### Sources

| Field | Type | Description |
|-------|------|-------------|
| `kind` | string | Source type: `nvd`, `osv`, `github_release`, `github_issue`, `epss`, `kev`, `deps_dev` |
| `url` | string | Source URL |

#### Timestamps

| Field | Type | Description |
|-------|------|-------------|
| `generatedAt` | datetime | When this intelligence was generated (ISO 8601) |
| `expiresAt` | datetime | When this intelligence should be refreshed (ISO 8601) |

---

## Complete Example

See [examples/kb/cve-mapping-with-intel.yaml](../examples/kb/cve-mapping-with-intel.yaml) for a complete example of a CveMapping with the `emphere.dev/intel` extension.

---

## Versioning

Extension schemas are versioned independently of the core OVRSE spec. Breaking changes to an extension schema SHOULD result in a new namespace (e.g., `emphere.dev/intel/v2`).

Current versions:
- `emphere.dev/intel` - v1 (this document)

---

## Intelligence Quality & Feedback

The `emphere.dev/intel` extension is generated by Emphere and continuously improved through multiple feedback channels:

1. **Community feedback** - Users report issues via landing page widget or CLI
2. **Enterprise feedback** - Ground truth from remediation execution outcomes
3. **Re-analysis** - Flagged CVEs are re-researched with improved prompts

This feedback loop is implementation-specific to Emphere and does NOT require changes to the OVRSE document schema. Intelligence quality improvements are reflected in future analyses, not stored as fields on existing documents.

For details on the feedback mechanism, see the Emphere documentation.
