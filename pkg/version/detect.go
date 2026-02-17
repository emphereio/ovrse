package version

import (
	"regexp"
	"strings"
)

// Patterns for detecting version formats from version strings.
var (
	// RPM patterns: epoch or distro suffixes
	rpmEpochPattern  = regexp.MustCompile(`^\d+:`)
	rpmDistroPattern = regexp.MustCompile(`\.(el|fc|amzn|centos|rhel)\d+`)

	// Debian patterns
	debPattern = regexp.MustCompile(`(\+deb|~deb|ubuntu|\.debian)`)

	// Alpine pattern: -rN suffix
	alpinePattern = regexp.MustCompile(`-r\d+$`)

	// Semver pattern: X.Y.Z with optional prerelease
	semverPattern = regexp.MustCompile(`^v?\d+\.\d+\.\d+(-[a-zA-Z0-9]+)?`)

	// Maven pattern: qualifiers
	mavenPattern = regexp.MustCompile(`-(SNAPSHOT|RELEASE|FINAL|GA|RC\d*|M\d+)$`)
)

// Distro markers that indicate a distribution-packaged version.
var distroMarkers = []string{
	"+deb", "~deb", ".deb",
	"ubuntu", ".ubuntu",
	".el", ".fc", ".amzn", ".centos", ".rhel",
	".suse", ".sles",
	"-r", // Alpine (must check with regex)
}

// DetectFormat attempts to detect the version format from a version string.
// The hint parameter can provide additional context (e.g., ecosystem name).
func DetectFormat(version string, hint string) Format {
	// Check hint first
	if hint != "" {
		if f := ParseFormat(strings.ToLower(hint)); f != UnknownFormat {
			return f
		}
	}

	version = strings.TrimSpace(version)
	if version == "" {
		return GenericFormat
	}

	// Check for epoch (RPM or Debian style)
	if rpmEpochPattern.MatchString(version) {
		// Has epoch, could be RPM or Debian
		// Check for Debian markers
		if debPattern.MatchString(version) {
			return DebFormat
		}
		// Check for RPM markers
		if rpmDistroPattern.MatchString(version) {
			return RpmFormat
		}
		// Default to RPM for epoch without other markers
		return RpmFormat
	}

	// Check for Debian patterns
	if debPattern.MatchString(version) {
		return DebFormat
	}

	// Check for RPM distro patterns
	if rpmDistroPattern.MatchString(version) {
		return RpmFormat
	}

	// Check for Alpine pattern
	if alpinePattern.MatchString(version) {
		return ApkFormat
	}

	// Check for Maven qualifiers
	if mavenPattern.MatchString(strings.ToUpper(version)) {
		return MavenFormat
	}

	// Check for semver pattern
	if semverPattern.MatchString(version) {
		return SemverFormat
	}

	// Default to generic
	return GenericFormat
}

// VersionsComparable checks if two versions can be meaningfully compared.
// Returns false if one is a distro-packaged version and the other is upstream.
func VersionsComparable(v1, v2, ecosystem string) bool {
	v1HasDistro := hasDistroMarker(v1)
	v2HasDistro := hasDistroMarker(v2)

	// Both have or both don't have distro markers - comparable
	if v1HasDistro == v2HasDistro {
		return true
	}

	// One has distro marker, other doesn't - not comparable
	// Exception: if they look like the same base version
	return false
}

// hasDistroMarker checks if a version string contains distribution-specific markers.
func hasDistroMarker(v string) bool {
	v = strings.ToLower(v)

	for _, marker := range distroMarkers {
		if marker == "-r" {
			// Alpine revision needs regex
			if alpinePattern.MatchString(v) {
				return true
			}
		} else if strings.Contains(v, marker) {
			return true
		}
	}

	return false
}

// IsDistroVersion returns true if the version appears to be from a distribution package.
func IsDistroVersion(v string) bool {
	return hasDistroMarker(v)
}

// FormatForEcosystem returns the expected version format for an ecosystem name.
func FormatForEcosystem(ecosystem string) Format {
	ecosystem = strings.ToLower(strings.TrimSpace(ecosystem))

	switch ecosystem {
	case "npm", "node", "nodejs":
		return SemverFormat
	case "go", "golang":
		return SemverFormat
	case "cargo", "rust", "crates.io":
		return SemverFormat
	case "pypi", "pip", "python":
		return PEP440Format
	case "deb", "debian", "ubuntu", "dpkg":
		return DebFormat
	case "rpm", "rhel", "centos", "fedora", "yum", "dnf", "amazon linux":
		return RpmFormat
	case "apk", "alpine":
		return ApkFormat
	case "maven", "java", "gradle", "mvn":
		return MavenFormat
	case "gem", "rubygems", "ruby":
		return SemverFormat // Ruby uses semver-like versions
	case "nuget", "dotnet", ".net":
		return SemverFormat
	default:
		return GenericFormat
	}
}
