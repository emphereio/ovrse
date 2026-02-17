// Package version provides comprehensive version comparison for multiple ecosystems.
// It supports semver (npm, Go, Cargo), PEP 440 (Python), Debian, RPM, Alpine, and Maven.
package version

import "fmt"

// Format represents a version format/ecosystem.
type Format int

const (
	UnknownFormat Format = iota
	SemverFormat         // npm, Go, Cargo, Rust
	PEP440Format         // Python/PyPI
	DebFormat            // Debian/Ubuntu
	RpmFormat            // RHEL, CentOS, Fedora, Amazon Linux
	ApkFormat            // Alpine Linux
	MavenFormat          // Java/Maven
	GenericFormat        // Fallback loose comparison
)

// String returns the string representation of the format.
func (f Format) String() string {
	switch f {
	case SemverFormat:
		return "semver"
	case PEP440Format:
		return "pep440"
	case DebFormat:
		return "deb"
	case RpmFormat:
		return "rpm"
	case ApkFormat:
		return "apk"
	case MavenFormat:
		return "maven"
	case GenericFormat:
		return "generic"
	default:
		return "unknown"
	}
}

// ParseFormat parses a format string into a Format.
func ParseFormat(s string) Format {
	switch s {
	case "semver", "npm", "go", "cargo", "rust", "node":
		return SemverFormat
	case "pep440", "pypi", "pip", "python":
		return PEP440Format
	case "deb", "debian", "ubuntu", "dpkg":
		return DebFormat
	case "rpm", "rhel", "centos", "fedora", "yum", "dnf":
		return RpmFormat
	case "apk", "alpine":
		return ApkFormat
	case "maven", "java", "gradle":
		return MavenFormat
	case "generic":
		return GenericFormat
	default:
		return UnknownFormat
	}
}

// Version represents a parsed version that can be compared.
type Version interface {
	// Compare returns -1 if v < other, 0 if v == other, 1 if v > other.
	Compare(other Version) int
	// String returns the original version string.
	String() string
	// Format returns the version format.
	Format() Format
}

// CompareResult represents the result of a version comparison.
type CompareResult int

const (
	CompareLess    CompareResult = -1
	CompareEqual   CompareResult = 0
	CompareGreater CompareResult = 1
	CompareError   CompareResult = -2 // Versions not comparable
)

// Compare compares two version strings using the specified format.
// Returns -1 if v1 < v2, 0 if v1 == v2, 1 if v1 > v2.
// Returns error if versions cannot be compared.
func Compare(v1, v2 string, format Format) (int, error) {
	switch format {
	case SemverFormat:
		return CompareSemver(v1, v2)
	case PEP440Format:
		return ComparePEP440(v1, v2)
	case DebFormat:
		return CompareDebian(v1, v2)
	case RpmFormat:
		return CompareRPM(v1, v2)
	case ApkFormat:
		return CompareAlpine(v1, v2)
	case MavenFormat:
		return CompareMaven(v1, v2)
	case GenericFormat, UnknownFormat:
		return CompareGeneric(v1, v2)
	default:
		return 0, fmt.Errorf("unsupported format: %s", format)
	}
}

// MustCompare is like Compare but returns 0 on error.
func MustCompare(v1, v2 string, format Format) int {
	result, err := Compare(v1, v2, format)
	if err != nil {
		return 0
	}
	return result
}

// ParseVersion parses a version string into a Version interface.
// If format is UnknownFormat, auto-detection is attempted.
func ParseVersion(v string, format Format) (Version, error) {
	if format == UnknownFormat {
		format = DetectFormat(v, "")
	}

	switch format {
	case SemverFormat:
		return NewSemVer(v)
	case PEP440Format:
		return NewPEP440Version(v)
	case DebFormat:
		return NewDebianVersion(v), nil
	case RpmFormat:
		return NewRPMVersion(v), nil
	case ApkFormat:
		return NewAlpineVersion(v), nil
	case MavenFormat:
		return NewMavenVersion(v), nil
	case GenericFormat:
		return NewGenericVersion(v), nil
	default:
		return NewGenericVersion(v), nil
	}
}

// SafeCompare compares versions with format validation.
// Returns an error if versions are not comparable (different ecosystems).
func SafeCompare(v1, v2 string, format Format) (int, error) {
	// Check if versions are comparable
	if !VersionsComparable(v1, v2, format.String()) {
		return 0, fmt.Errorf("versions not comparable: %q vs %q (mixed distro/upstream versions)", v1, v2)
	}
	return Compare(v1, v2, format)
}
