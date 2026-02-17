package version

import (
	"regexp"
	"strconv"
	"strings"
)

var apkRevisionRegex = regexp.MustCompile(`^(.+)-r(\d+)$`)

// CompareAlpine compares two Alpine versions.
// Format: version-rN where N is the revision number.
func CompareAlpine(v1, v2 string) (int, error) {
	a1 := parseAlpineVersion(v1)
	a2 := parseAlpineVersion(v2)
	return a1.Compare(a2), nil
}

// AlpineVersion represents a parsed Alpine version.
type AlpineVersion struct {
	original string
	base     string
	revision int
}

// parseAlpineVersion parses an Alpine version string.
func parseAlpineVersion(v string) *AlpineVersion {
	v = strings.TrimSpace(v)

	av := &AlpineVersion{original: v}

	// Try to extract -rN suffix
	if matches := apkRevisionRegex.FindStringSubmatch(v); matches != nil {
		av.base = matches[1]
		revision, err := strconv.Atoi(matches[2])
		if err == nil && revision >= 0 {
			av.revision = revision
		}
		// Invalid or negative revision defaults to 0
	} else {
		av.base = v
		av.revision = 0
	}

	return av
}

// Compare implements Version.Compare.
func (a *AlpineVersion) Compare(other Version) int {
	if other == nil {
		return 1 // non-nil > nil
	}
	// Type assert to *AlpineVersion for optimized comparison
	if o, ok := other.(*AlpineVersion); ok {
		return a.compareAlpineVersion(o)
	}
	// Fallback to string-based comparison
	cmp, _ := CompareAlpine(a.String(), other.String())
	return cmp
}

// compareAlpineVersion compares two AlpineVersion instances.
func (a *AlpineVersion) compareAlpineVersion(other *AlpineVersion) int {
	// Compare base versions first
	cmp, _ := CompareGeneric(a.base, other.base)
	if cmp != 0 {
		return cmp
	}

	// Compare revisions
	if a.revision < other.revision {
		return -1
	}
	if a.revision > other.revision {
		return 1
	}
	return 0
}

// String implements Version.String.
func (a *AlpineVersion) String() string {
	return a.original
}

// Format implements Version.Format.
func (a *AlpineVersion) Format() Format {
	return ApkFormat
}

// NewAlpineVersion creates a new AlpineVersion from a version string.
func NewAlpineVersion(v string) *AlpineVersion {
	return parseAlpineVersion(v)
}
