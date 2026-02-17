package version

import (
	"strconv"
	"strings"
)

// CompareRPM compares two RPM versions.
// Format: [epoch:]version[-release]
// Comparison order: epoch (numeric) > version > release
func CompareRPM(v1, v2 string) (int, error) {
	r1 := parseRPMVersion(v1)
	r2 := parseRPMVersion(v2)
	return r1.Compare(r2), nil
}

// RPMVersion represents a parsed RPM version.
type RPMVersion struct {
	original string
	epoch    int
	version  string
	release  string
}

// parseRPMVersion parses an RPM version string.
func parseRPMVersion(v string) *RPMVersion {
	v = strings.TrimSpace(v)

	rv := &RPMVersion{original: v}

	// Extract epoch (before first colon)
	if idx := strings.Index(v, ":"); idx > 0 {
		epochStr := v[:idx]
		epoch, err := strconv.Atoi(epochStr)
		if err == nil && epoch >= 0 {
			rv.epoch = epoch
		}
		// Invalid or negative epoch defaults to 0
		v = v[idx+1:]
	}

	// Extract release (after first hyphen)
	// RPM uses first hyphen, unlike Debian which uses last
	if idx := strings.Index(v, "-"); idx > 0 {
		rv.version = v[:idx]
		rv.release = v[idx+1:]
	} else {
		rv.version = v
		rv.release = ""
	}

	return rv
}

// Compare implements Version.Compare.
func (r *RPMVersion) Compare(other Version) int {
	if other == nil {
		return 1 // non-nil > nil
	}
	// Type assert to *RPMVersion for optimized comparison
	if o, ok := other.(*RPMVersion); ok {
		return r.compareRPMVersion(o)
	}
	// Fallback to string-based comparison
	cmp, _ := CompareRPM(r.String(), other.String())
	return cmp
}

// compareRPMVersion compares two RPMVersion instances.
func (r *RPMVersion) compareRPMVersion(other *RPMVersion) int {
	// Compare epochs first
	if r.epoch != other.epoch {
		if r.epoch < other.epoch {
			return -1
		}
		return 1
	}

	// Compare versions using RPM algorithm
	cmp := compareRPMString(r.version, other.version)
	if cmp != 0 {
		return cmp
	}

	// Compare releases
	return compareRPMString(r.release, other.release)
}

// String implements Version.String.
func (r *RPMVersion) String() string {
	return r.original
}

// Format implements Version.Format.
func (r *RPMVersion) Format() Format {
	return RpmFormat
}

// compareRPMString compares version strings using RPM's comparison algorithm.
// This is similar to Debian's but without the tilde special case.
func compareRPMString(a, b string) int {
	ai, bi := 0, 0

	for ai < len(a) || bi < len(b) {
		// Skip non-alphanumeric characters
		for ai < len(a) && !isAlphaNum(a[ai]) {
			ai++
		}
		for bi < len(b) && !isAlphaNum(b[bi]) {
			bi++
		}

		// Extract alphanumeric segment
		aStart, bStart := ai, bi

		// Check if this is a digit or alpha segment
		aIsDigit := ai < len(a) && isDigit(a[ai])
		bIsDigit := bi < len(b) && isDigit(b[bi])

		// Extract segment
		if aIsDigit {
			for ai < len(a) && isDigit(a[ai]) {
				ai++
			}
		} else {
			for ai < len(a) && isAlpha(a[ai]) {
				ai++
			}
		}

		if bIsDigit {
			for bi < len(b) && isDigit(b[bi]) {
				bi++
			}
		} else {
			for bi < len(b) && isAlpha(b[bi]) {
				bi++
			}
		}

		aSeg := a[aStart:ai]
		bSeg := b[bStart:bi]

		// Handle empty segments
		if aSeg == "" && bSeg == "" {
			continue
		}
		if aSeg == "" {
			return -1
		}
		if bSeg == "" {
			return 1
		}

		// Compare segments
		// Numeric segments are compared numerically
		// Alpha segments are compared lexicographically
		// Numeric segments are newer than alpha segments
		if aIsDigit && bIsDigit {
			// Both numeric - compare numerically
			cmp := compareRPMDigit(aSeg, bSeg)
			if cmp != 0 {
				return cmp
			}
		} else if aIsDigit {
			// Numeric is newer than alpha
			return 1
		} else if bIsDigit {
			return -1
		} else {
			// Both alpha - compare lexicographically
			if aSeg < bSeg {
				return -1
			}
			if aSeg > bSeg {
				return 1
			}
		}
	}

	return 0
}

// compareRPMDigit compares two numeric strings numerically.
func compareRPMDigit(a, b string) int {
	// Strip leading zeros
	a = strings.TrimLeft(a, "0")
	b = strings.TrimLeft(b, "0")

	if a == "" {
		a = "0"
	}
	if b == "" {
		b = "0"
	}

	// Compare by length first
	if len(a) != len(b) {
		if len(a) < len(b) {
			return -1
		}
		return 1
	}

	// Same length, compare lexicographically
	if a < b {
		return -1
	}
	if a > b {
		return 1
	}
	return 0
}

// isAlpha returns true if byte is a letter.
func isAlpha(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

// isAlphaNum returns true if byte is alphanumeric.
func isAlphaNum(b byte) bool {
	return isAlpha(b) || isDigit(b)
}

// NewRPMVersion creates a new RPMVersion from a version string.
func NewRPMVersion(v string) *RPMVersion {
	return parseRPMVersion(v)
}
