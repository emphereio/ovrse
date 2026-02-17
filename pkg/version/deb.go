package version

import (
	"strconv"
	"strings"
	"unicode"
)

// CompareDebian compares two Debian versions.
// Format: [epoch:]upstream_version[-debian_revision]
// Comparison order: epoch (numeric) > upstream > revision
// Uses Debian string comparison algorithm where ~ sorts before empty.
func CompareDebian(v1, v2 string) (int, error) {
	d1 := parseDebianVersion(v1)
	d2 := parseDebianVersion(v2)
	return d1.Compare(d2), nil
}

// DebianVersion represents a parsed Debian version.
type DebianVersion struct {
	original string
	epoch    int
	upstream string
	revision string
}

// parseDebianVersion parses a Debian version string.
func parseDebianVersion(v string) *DebianVersion {
	v = strings.TrimSpace(v)

	dv := &DebianVersion{original: v}

	// Extract epoch (before first colon)
	if idx := strings.Index(v, ":"); idx > 0 {
		epochStr := v[:idx]
		epoch, err := strconv.Atoi(epochStr)
		if err == nil && epoch >= 0 {
			dv.epoch = epoch
		}
		// Invalid or negative epoch defaults to 0
		v = v[idx+1:]
	}

	// Extract revision (after last hyphen, but be careful with upstream versions that contain hyphens)
	// Debian policy: revision is after the last hyphen
	if idx := strings.LastIndex(v, "-"); idx > 0 {
		dv.upstream = v[:idx]
		dv.revision = v[idx+1:]
	} else {
		dv.upstream = v
		dv.revision = ""
	}

	return dv
}

// Compare implements Version.Compare.
func (d *DebianVersion) Compare(other Version) int {
	if other == nil {
		return 1 // non-nil > nil
	}
	// Type assert to *DebianVersion for optimized comparison
	if o, ok := other.(*DebianVersion); ok {
		return d.compareDebianVersion(o)
	}
	// Fallback to string-based comparison
	cmp, _ := CompareDebian(d.String(), other.String())
	return cmp
}

// compareDebianVersion compares two DebianVersion instances.
func (d *DebianVersion) compareDebianVersion(other *DebianVersion) int {
	// Compare epochs first
	if d.epoch != other.epoch {
		if d.epoch < other.epoch {
			return -1
		}
		return 1
	}

	// Compare upstream versions
	cmp := compareDebianString(d.upstream, other.upstream)
	if cmp != 0 {
		return cmp
	}

	// Compare revisions
	return compareDebianString(d.revision, other.revision)
}

// String implements Version.String.
func (d *DebianVersion) String() string {
	return d.original
}

// Format implements Version.Format.
func (d *DebianVersion) Format() Format {
	return DebFormat
}

// compareDebianString implements the Debian version string comparison algorithm.
// The algorithm alternates between comparing non-digit and digit sequences.
// Tilde (~) sorts before everything, including empty string.
func compareDebianString(a, b string) int {
	ai, bi := 0, 0

	for ai < len(a) || bi < len(b) {
		// Compare non-digit portions
		var aNonDigit, bNonDigit string
		for ai < len(a) && !isDigit(a[ai]) {
			aNonDigit += string(a[ai])
			ai++
		}
		for bi < len(b) && !isDigit(b[bi]) {
			bNonDigit += string(b[bi])
			bi++
		}

		cmp := compareDebianNonDigit(aNonDigit, bNonDigit)
		if cmp != 0 {
			return cmp
		}

		// Compare digit portions numerically
		var aDigit, bDigit string
		for ai < len(a) && isDigit(a[ai]) {
			aDigit += string(a[ai])
			ai++
		}
		for bi < len(b) && isDigit(b[bi]) {
			bDigit += string(b[bi])
			bi++
		}

		cmp = compareDebianDigit(aDigit, bDigit)
		if cmp != 0 {
			return cmp
		}
	}

	return 0
}

// compareDebianNonDigit compares non-digit portions using Debian ordering.
// Letters sort in ASCII order. Tilde sorts before everything, including empty.
// All other characters (including empty) sort before letters.
func compareDebianNonDigit(a, b string) int {
	ai, bi := 0, 0

	for ai < len(a) || bi < len(b) {
		var ac, bc int

		if ai < len(a) {
			ac = debianCharOrder(rune(a[ai]))
			ai++
		} else {
			ac = debianCharOrder(0) // Empty
		}

		if bi < len(b) {
			bc = debianCharOrder(rune(b[bi]))
			bi++
		} else {
			bc = debianCharOrder(0) // Empty
		}

		if ac != bc {
			if ac < bc {
				return -1
			}
			return 1
		}
	}

	return 0
}

// debianCharOrder returns the sort order for a character in Debian comparison.
// Tilde (~) = -1 (sorts before everything)
// Empty/0 = 0
// Non-letters = 1
// Letters = ASCII value + 256 (sorts after non-letters)
func debianCharOrder(c rune) int {
	if c == '~' {
		return -1
	}
	if c == 0 {
		return 0
	}
	if unicode.IsLetter(c) {
		return int(c) + 256
	}
	return int(c)
}

// compareDebianDigit compares digit portions numerically.
func compareDebianDigit(a, b string) int {
	// Strip leading zeros for numeric comparison
	a = strings.TrimLeft(a, "0")
	b = strings.TrimLeft(b, "0")

	// Handle empty strings (all zeros or empty)
	if a == "" {
		a = "0"
	}
	if b == "" {
		b = "0"
	}

	// Compare by length first (longer number is greater)
	if len(a) != len(b) {
		if len(a) < len(b) {
			return -1
		}
		return 1
	}

	// Same length, compare lexicographically (works for same-length numbers)
	if a < b {
		return -1
	}
	if a > b {
		return 1
	}
	return 0
}

// isDigit returns true if byte is a digit.
func isDigit(b byte) bool {
	return b >= '0' && b <= '9'
}

// NewDebianVersion creates a new DebianVersion from a version string.
func NewDebianVersion(v string) *DebianVersion {
	return parseDebianVersion(v)
}
