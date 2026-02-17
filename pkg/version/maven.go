package version

import (
	"strings"
)

// Maven qualifier ordering.
// SNAPSHOT < RELEASE/FINAL/GA < (none/empty)
var mavenQualifierOrder = map[string]int{
	"snapshot": 0,
	"alpha":    1,
	"a":        1,
	"beta":     2,
	"b":        2,
	"milestone": 3,
	"m":        3,
	"rc":       4,
	"cr":       4,
	"release":  5,
	"final":    5,
	"ga":       5,
	"":         6, // No qualifier
	"sp":       7, // Service pack
}

// CompareMaven compares two Maven versions.
// Qualifier ordering: SNAPSHOT < alpha < beta < milestone < rc < RELEASE/FINAL/GA < (none) < sp
func CompareMaven(v1, v2 string) (int, error) {
	m1 := parseMavenVersion(v1)
	m2 := parseMavenVersion(v2)
	return m1.Compare(m2), nil
}

// MavenVersion represents a parsed Maven version.
type MavenVersion struct {
	original  string
	base      string
	qualifier string
}

// parseMavenVersion parses a Maven version string.
func parseMavenVersion(v string) *MavenVersion {
	v = strings.TrimSpace(v)

	mv := &MavenVersion{original: v}

	// Look for qualifier after hyphen
	if idx := strings.LastIndex(v, "-"); idx > 0 {
		mv.base = v[:idx]
		mv.qualifier = strings.ToLower(v[idx+1:])
	} else {
		mv.base = v
		mv.qualifier = ""
	}

	return mv
}

// Compare implements Version.Compare.
func (m *MavenVersion) Compare(other Version) int {
	if other == nil {
		return 1 // non-nil > nil
	}
	// Type assert to *MavenVersion for optimized comparison
	if o, ok := other.(*MavenVersion); ok {
		return m.compareMavenVersion(o)
	}
	// Fallback to string-based comparison
	cmp, _ := CompareMaven(m.String(), other.String())
	return cmp
}

// compareMavenVersion compares two MavenVersion instances.
func (m *MavenVersion) compareMavenVersion(other *MavenVersion) int {
	// Compare base versions first
	cmp, _ := CompareGeneric(m.base, other.base)
	if cmp != 0 {
		return cmp
	}

	// Compare qualifiers
	mOrder := mavenQualifierOrder[m.qualifier]
	oOrder := mavenQualifierOrder[other.qualifier]

	// Unknown qualifiers default to before (none)
	if _, ok := mavenQualifierOrder[m.qualifier]; !ok {
		mOrder = 5 // Same as RELEASE
	}
	if _, ok := mavenQualifierOrder[other.qualifier]; !ok {
		oOrder = 5
	}

	if mOrder < oOrder {
		return -1
	}
	if mOrder > oOrder {
		return 1
	}

	// Same qualifier order means they are equivalent (e.g., RELEASE == FINAL == GA)
	return 0
}

// String implements Version.String.
func (m *MavenVersion) String() string {
	return m.original
}

// Format implements Version.Format.
func (m *MavenVersion) Format() Format {
	return MavenFormat
}

// NewMavenVersion creates a new MavenVersion from a version string.
func NewMavenVersion(v string) *MavenVersion {
	return parseMavenVersion(v)
}
