package version

import (
	"strings"

	"github.com/Masterminds/semver/v3"
)

// CompareSemver compares two semantic versions.
// Handles v prefix, prerelease ordering (alpha < beta < rc < release),
// and ignores build metadata in comparison.
func CompareSemver(v1, v2 string) (int, error) {
	v1 = normalizeSemver(v1)
	v2 = normalizeSemver(v2)

	// Try strict semver parsing first
	sv1, err1 := semver.NewVersion(v1)
	sv2, err2 := semver.NewVersion(v2)

	if err1 == nil && err2 == nil {
		return sv1.Compare(sv2), nil
	}

	// Fall back to generic comparison if parsing fails
	return CompareGeneric(v1, v2)
}

// normalizeSemver prepares a version string for semver parsing.
func normalizeSemver(v string) string {
	v = strings.TrimSpace(v)

	// Strip v/V prefix for comparison
	v = strings.TrimPrefix(v, "v")
	v = strings.TrimPrefix(v, "V")

	return v
}

// SemVer wraps a semver.Version for the Version interface.
type SemVer struct {
	original string
	parsed   *semver.Version
}

// NewSemVer creates a new SemVer from a version string.
func NewSemVer(v string) (*SemVer, error) {
	normalized := normalizeSemver(v)
	parsed, err := semver.NewVersion(normalized)
	if err != nil {
		return nil, err
	}
	return &SemVer{
		original: v,
		parsed:   parsed,
	}, nil
}

// Compare implements Version.Compare.
func (s *SemVer) Compare(other Version) int {
	if other == nil {
		return 1 // non-nil > nil
	}
	otherSemver, ok := other.(*SemVer)
	if !ok {
		// Fall back to generic comparison
		cmp, _ := CompareGeneric(s.String(), other.String())
		return cmp
	}
	return s.parsed.Compare(otherSemver.parsed)
}

// String implements Version.String.
func (s *SemVer) String() string {
	return s.original
}

// Format implements Version.Format.
func (s *SemVer) Format() Format {
	return SemverFormat
}

// Major returns the major version number.
func (s *SemVer) Major() uint64 {
	return s.parsed.Major()
}

// Minor returns the minor version number.
func (s *SemVer) Minor() uint64 {
	return s.parsed.Minor()
}

// Patch returns the patch version number.
func (s *SemVer) Patch() uint64 {
	return s.parsed.Patch()
}

// Prerelease returns the prerelease string.
func (s *SemVer) Prerelease() string {
	return s.parsed.Prerelease()
}

// ParseSemverConstraint parses a semver constraint string.
// Supports: =, !=, >, <, >=, <=, ~, ^, and ranges.
func ParseSemverConstraint(constraint string) (*semver.Constraints, error) {
	return semver.NewConstraint(constraint)
}

// SemverSatisfies checks if a version satisfies a constraint.
func SemverSatisfies(version, constraint string) (bool, error) {
	v := normalizeSemver(version)
	sv, err := semver.NewVersion(v)
	if err != nil {
		return false, err
	}

	c, err := semver.NewConstraint(constraint)
	if err != nil {
		return false, err
	}

	return c.Check(sv), nil
}
