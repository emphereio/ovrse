package version

import (
	"strings"

	pep440 "github.com/aquasecurity/go-pep440-version"
)

// ComparePEP440 compares two PEP 440 Python versions.
// Ordering: dev < alpha < beta < rc < release < post
// Handles epochs (1!1.0.0) and strips local versions for comparison.
func ComparePEP440(v1, v2 string) (int, error) {
	v1 = normalizePEP440(v1)
	v2 = normalizePEP440(v2)

	pv1, err1 := pep440.Parse(v1)
	pv2, err2 := pep440.Parse(v2)

	if err1 == nil && err2 == nil {
		if pv1.Equal(pv2) {
			return 0, nil
		}
		if pv1.LessThan(pv2) {
			return -1, nil
		}
		return 1, nil
	}

	// Fall back to generic comparison if parsing fails
	return CompareGeneric(v1, v2)
}

// normalizePEP440 prepares a version string for PEP 440 parsing.
func normalizePEP440(v string) string {
	v = strings.TrimSpace(v)

	// Strip local version for comparison (1.0.0+local -> 1.0.0)
	if idx := strings.Index(v, "+"); idx > 0 {
		// Keep only the public version
		v = v[:idx]
	}

	return v
}

// PEP440Version wraps a pep440.Version for the Version interface.
type PEP440Version struct {
	original string
	parsed   pep440.Version
}

// NewPEP440Version creates a new PEP440Version from a version string.
func NewPEP440Version(v string) (*PEP440Version, error) {
	normalized := normalizePEP440(v)
	parsed, err := pep440.Parse(normalized)
	if err != nil {
		return nil, err
	}
	return &PEP440Version{
		original: v,
		parsed:   parsed,
	}, nil
}

// Compare implements Version.Compare.
func (p *PEP440Version) Compare(other Version) int {
	if other == nil {
		return 1 // non-nil > nil
	}
	otherPEP, ok := other.(*PEP440Version)
	if !ok {
		// Fall back to generic comparison
		cmp, _ := CompareGeneric(p.String(), other.String())
		return cmp
	}
	if p.parsed.Equal(otherPEP.parsed) {
		return 0
	}
	if p.parsed.LessThan(otherPEP.parsed) {
		return -1
	}
	return 1
}

// String implements Version.String.
func (p *PEP440Version) String() string {
	return p.original
}

// Format implements Version.Format.
func (p *PEP440Version) Format() Format {
	return PEP440Format
}
