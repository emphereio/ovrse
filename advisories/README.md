# OVRSE Advisories

This directory contains pre-computed, risk-prioritized CVE advisories by ecosystem. Each file lists CVEs that meet strict "must patch immediately" criteria.

For the full explanation of how advisories work, see [docs/ADVISORIES.md](../docs/ADVISORIES.md).

## Supported Ecosystems

| Ecosystem | File | Package Managers |
|-----------|------|------------------|
| npm | [`npm.json`](./npm.json) | npm, yarn, pnpm |
| PyPI | [`pypi.json`](./pypi.json) | pip, poetry, pipenv |
| Go | [`go.json`](./go.json) | go modules |
| Maven | [`maven.json`](./maven.json) | Maven, Gradle |
| Cargo | [`cargo.json`](./cargo.json) | Cargo |
| RubyGems | [`gem.json`](./gem.json) | Bundler |
| **Global** | [`global.json`](./global.json) | Cross-ecosystem summary |

**Planned:** NuGet (.NET), Packagist (PHP)

## Update Frequency

Advisories are synced from [Emphere Intel](https://emphere.dev) every 4 hours via GitHub Actions. Each file includes `last_updated` and `expires_at` timestamps.

## Ecosystem Advisory Schema

Each ecosystem file (`npm.json`, `pypi.json`, etc.) has the following structure:

> **Note**: The counts (`total_cves`, `critical_count`, etc.) reflect CVEs that passed the gating thresholds—not all CVEs in the OVRSE knowledge base.

```json
{
  "ecosystem": "npm",
  "last_updated": "2026-02-15T12:00:00Z",
  "expires_at": "2026-02-15T16:00:00Z",
  "total_cves": 6,
  "critical_count": 2,
  "high_count": 3,
  "kev_count": 3,
  "cves": [
    {
      "cve_id": "CVE-2026-1234",
      "summary": "Critical RCE in package-name allows...",
      "severity": "critical",
      "cvss_score": 9.8,
      "epss_percentile": 0.85,
      "kev_listed": true,
      "kev_date_added": "2026-02-10T00:00:00Z",
      "has_fix": true,
      "fix_version": "4.17.21",
      "packages": ["lodash"],
      "published_date": "2026-02-01T00:00:00Z",
      "added_to_advisory": "2026-02-01T12:00:00Z",
      "priority_score": 95.0
    }
  ],
  "top_packages": [
    {"package": "lodash", "count": 2}
  ]
}
```

## Global Advisory Schema

The `global.json` file has a different structure—it summarizes all ecosystems:

```json
{
  "window": "30d",
  "total_cves": 7,
  "total_ecosystems": 6,
  "last_updated": "2026-02-15T12:00:00Z",
  "ecosystems": {
    "npm": {
      "ecosystem": "npm",
      "total_cves": 6,
      "critical_count": 2,
      "high_count": 2,
      "kev_count": 3,
      "with_fix_count": 6,
      "last_updated": "2026-02-15T12:00:00Z"
    }
  },
  "top_critical": [
    {
      "cve_id": "CVE-2026-1234",
      "severity": "critical",
      "cvss_score": 9.8,
      "kev_listed": true,
      "packages": ["lodash"],
      "priority_score": 95.0
    }
  ]
}
```

| Field | Description |
|-------|-------------|
| `ecosystems` | Summary stats for each ecosystem |
| `top_critical` | Top 10 critical CVEs across all ecosystems |

## Field Reference

| Field | Type | Description |
|-------|------|-------------|
| `cve_id` | string | CVE identifier |
| `summary` | string | AI-generated remediation summary |
| `severity` | enum | `critical`, `high`, `medium`, `low` |
| `cvss_score` | number | CVSS base score (0-10) |
| `epss_percentile` | number | EPSS percentile as 0-1 float (e.g., 0.85 = 85th percentile) |
| `kev_listed` | boolean | In CISA KEV catalog |
| `kev_date_added` | datetime | When added to KEV (ISO 8601 UTC) |
| `has_fix` | boolean | Whether a fix exists |
| `fix_version` | string | Version that fixes the CVE |
| `packages` | string[] | Affected package names |
| `published_date` | datetime | NVD publish date (ISO 8601 UTC) |
| `added_to_advisory` | datetime | When CVE was first added to advisory (ISO 8601 UTC) |
| `priority_score` | number | Computed priority (0-100) |

## How to Use

### Direct Download

```bash
# Get npm advisory
curl -s https://raw.githubusercontent.com/emphereio/ovrse/main/advisories/npm.json

# Pretty print top 5 CVEs
curl -s https://raw.githubusercontent.com/emphereio/ovrse/main/advisories/npm.json | jq '.cves[:5]'

# Get only KEV-listed CVEs
curl -s https://raw.githubusercontent.com/emphereio/ovrse/main/advisories/npm.json | jq '.cves | map(select(.kev_listed))'
```

### Check Your Dependencies

```bash
# Check package.json against npm advisory
curl -s https://raw.githubusercontent.com/emphereio/ovrse/main/advisories/npm.json > /tmp/npm-advisory.json

jq -r '.dependencies | keys[]' package.json | while read pkg; do
  match=$(jq --arg pkg "$pkg" '.cves[] | select(.packages[] == $pkg)' /tmp/npm-advisory.json)
  if [ -n "$match" ]; then
    echo "VULNERABLE: $pkg"
    echo "$match" | jq -r '"  \(.cve_id): \(.summary)"'
  fi
done
```

### Filter by Time Window

The JSON contains all CVEs from the last 30 days. To get only the last 7 days:

```bash
# Get CVEs from last 7 days
# Uses: kev_date_added (if KEV), else published_date, else added_to_advisory
CUTOFF=$(date -u -v-7d +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d '7 days ago' +%Y-%m-%dT%H:%M:%SZ)
curl -s https://raw.githubusercontent.com/emphereio/ovrse/main/advisories/npm.json | \
  jq --arg cutoff "$CUTOFF" '.cves | map(select(
    (.kev_date_added // .published_date // .added_to_advisory) >= $cutoff
  ))'
```

## Gating Thresholds

A CVE is included in the advisory if it meets **any** of these criteria:

| Criteria | Threshold | Rationale |
|----------|-----------|-----------|
| **KEV Listed** | Always included | Actively exploited in the wild |
| **EPSS Percentile** | >= 0.50 (50%) | High probability of exploitation |
| **CVSS Score** | >= 9.0 | Critical severity only |

CVEs below these thresholds are still available via the [Emphere Intel API](https://emphere.dev/mcp) on-demand.

## Contributing

### Report a Missing CVE

If a critical CVE is missing from the advisory:

1. Verify it meets the gating thresholds (KEV, EPSS >= 50%, or CVSS >= 9.0)
2. [Open an issue](https://github.com/emphereio/ovrse/issues/new?template=missing_cve.md)
3. Include: CVE ID, ecosystem, and why it should be included

### Report Incorrect Data

If advisory data is wrong:

1. [Open an issue](https://github.com/emphereio/ovrse/issues/new?template=incorrect_data.md)
2. Include: CVE ID, what's wrong, and sources showing the correct information

### Request a New Ecosystem

To request support for a new ecosystem:

1. [Open an issue](https://github.com/emphereio/ovrse/issues/new?template=new_ecosystem.md)
2. Include: ecosystem name, package manager, and vulnerability data sources

## License

Advisory data is provided under the same [Apache 2.0 license](../LICENSE) as the OVRSE project.
