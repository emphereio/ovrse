package version

import (
	"fmt"
	"strings"
)

// VulnerabilityStatus represents the vulnerability status of a version.
type VulnerabilityStatus int

const (
	StatusUnknown     VulnerabilityStatus = iota
	StatusNotAffected                     // Version predates vulnerability or is past last_affected
	StatusVulnerable                      // Version is in affected range
	StatusFixed                           // Version >= fix version
)

// String returns the string representation of the status.
func (s VulnerabilityStatus) String() string {
	switch s {
	case StatusNotAffected:
		return "not_affected"
	case StatusVulnerable:
		return "vulnerable"
	case StatusFixed:
		return "fixed"
	default:
		return "unknown"
	}
}

// CheckVulnerabilityStatus determines if a version is affected by a vulnerability.
//
// Parameters:
//   - current: The version to check
//   - introduced: Version where vulnerability was introduced (empty = from beginning)
//   - fixed: Version where vulnerability was fixed (empty = no fix available)
//   - lastAffected: Last version affected (empty = use fixed for upper bound)
//   - format: The version format to use for comparison
//
// Returns the vulnerability status and a human-readable explanation.
func CheckVulnerabilityStatus(current, introduced, fixed, lastAffected string, format Format) (VulnerabilityStatus, string) {
	current = strings.TrimSpace(current)
	introduced = strings.TrimSpace(introduced)
	fixed = strings.TrimSpace(fixed)
	lastAffected = strings.TrimSpace(lastAffected)

	if current == "" {
		return StatusUnknown, "no version specified"
	}

	// Check if version predates the vulnerability
	if introduced != "" && !isZeroVersion(introduced) {
		cmp, err := Compare(current, introduced, format)
		if err == nil && cmp < 0 {
			return StatusNotAffected, fmt.Sprintf("%s < %s (version predates vulnerability)", current, introduced)
		}
	}

	// Check if version is past last_affected
	if lastAffected != "" {
		cmp, err := Compare(current, lastAffected, format)
		if err == nil && cmp > 0 {
			return StatusNotAffected, fmt.Sprintf("%s > %s (past last affected version)", current, lastAffected)
		}
	}

	// Check if version is fixed
	if fixed != "" {
		cmp, err := Compare(current, fixed, format)
		if err == nil && cmp >= 0 {
			return StatusFixed, fmt.Sprintf("%s >= %s (patched)", current, fixed)
		}
	}

	// At this point, version is in vulnerable range
	if fixed != "" {
		return StatusVulnerable, fmt.Sprintf("%s is in vulnerable range [%s, %s)", current, effectiveIntroduced(introduced), fixed)
	}
	if lastAffected != "" {
		return StatusVulnerable, fmt.Sprintf("%s is in vulnerable range [%s, %s]", current, effectiveIntroduced(introduced), lastAffected)
	}

	// No fix or lastAffected specified, assume vulnerable if >= introduced
	return StatusVulnerable, fmt.Sprintf("%s >= %s (no fix available)", current, effectiveIntroduced(introduced))
}

// InRange checks if a version is within an affected range.
// The range is [introduced, fixed) - introduced is inclusive, fixed is exclusive.
func InRange(version, introduced, fixed string, format Format) (bool, error) {
	version = strings.TrimSpace(version)
	introduced = strings.TrimSpace(introduced)
	fixed = strings.TrimSpace(fixed)

	// Check if version >= introduced
	if introduced != "" && !isZeroVersion(introduced) {
		cmp, err := Compare(version, introduced, format)
		if err != nil {
			return false, err
		}
		if cmp < 0 {
			return false, nil // Version is before introduced
		}
	}

	// Check if version < fixed
	if fixed != "" {
		cmp, err := Compare(version, fixed, format)
		if err != nil {
			return false, err
		}
		if cmp >= 0 {
			return false, nil // Version is at or after fixed
		}
	}

	return true, nil
}

// IsFixed checks if a version is at or above the fix version.
func IsFixed(version, fixVersion string, format Format) (bool, error) {
	if fixVersion == "" {
		return false, nil
	}
	cmp, err := Compare(version, fixVersion, format)
	if err != nil {
		return false, err
	}
	return cmp >= 0, nil
}

// isZeroVersion returns true if the version represents "from the beginning".
// This includes "0", "0.0", "0.0.0" but NOT "0.1" or "0.0.1".
func isZeroVersion(v string) bool {
	v = strings.TrimSpace(v)
	if v == "" || v == "0" {
		return true
	}

	// Check for 0.0, 0.0.0, etc.
	parts := strings.Split(v, ".")
	for _, part := range parts {
		// Strip any non-numeric suffix
		numPart := strings.TrimRight(part, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-_")
		if numPart != "0" && numPart != "" {
			return false
		}
	}
	return true
}

// effectiveIntroduced returns "0" if introduced is empty or zero, otherwise returns introduced.
func effectiveIntroduced(introduced string) string {
	if introduced == "" || isZeroVersion(introduced) {
		return "0"
	}
	return introduced
}
