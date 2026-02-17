package version

import (
	"testing"
)

func TestCompareSemver(t *testing.T) {
	tests := []struct {
		v1, v2 string
		want   int
	}{
		// Basic comparisons
		{"1.0.0", "2.0.0", -1},
		{"2.0.0", "1.0.0", 1},
		{"1.0.0", "1.0.0", 0},

		// Minor and patch
		{"1.0.0", "1.1.0", -1},
		{"1.0.0", "1.0.1", -1},
		{"1.1.0", "1.0.1", 1},

		// v prefix handling
		{"v1.0.0", "1.0.0", 0},
		{"v1.0.0", "v2.0.0", -1},

		// Prerelease ordering
		{"1.0.0-alpha", "1.0.0-beta", -1},
		{"1.0.0-beta", "1.0.0-rc", -1},
		{"1.0.0-rc", "1.0.0", -1},
		{"1.0.0-alpha.1", "1.0.0-alpha.2", -1},

		// Build metadata (should be ignored)
		{"1.0.0+build1", "1.0.0+build2", 0},
		{"1.0.0+build", "1.0.0", 0},

		// Real-world examples from Intel-engine tests
		{"4.17.19", "4.17.21", -1}, // lodash patch
		{"6.10.3", "6.14.1", -1},   // qs minor
	}

	for _, tt := range tests {
		t.Run(tt.v1+"_vs_"+tt.v2, func(t *testing.T) {
			got, err := CompareSemver(tt.v1, tt.v2)
			if err != nil {
				t.Errorf("CompareSemver(%q, %q) error = %v", tt.v1, tt.v2, err)
				return
			}
			if got != tt.want {
				t.Errorf("CompareSemver(%q, %q) = %d, want %d", tt.v1, tt.v2, got, tt.want)
			}
		})
	}
}

func TestComparePEP440(t *testing.T) {
	tests := []struct {
		v1, v2 string
		want   int
	}{
		// Basic comparisons
		{"1.0.0", "2.0.0", -1},
		{"2.0.0", "1.0.0", 1},
		{"1.0.0", "1.0.0", 0},

		// Pre-release ordering
		{"1.0.0a1", "1.0.0b1", -1},
		{"1.0.0b1", "1.0.0rc1", -1},
		{"1.0.0rc1", "1.0.0", -1},
		{"1.0.0.dev1", "1.0.0a1", -1},

		// Post releases
		{"1.0.0", "1.0.0.post1", -1},
		{"1.0.0.post1", "1.0.0.post2", -1},

		// Epochs
		{"1.0.0", "1!0.0.1", -1}, // epoch 1 > no epoch
		{"1!1.0.0", "2.0.0", 1},  // epoch wins

		// Real-world examples
		{"2.31.0", "2.32.5", -1}, // requests minor upgrade
		{"3.3.2", "41.0.0", -1},  // cryptography major upgrade
	}

	for _, tt := range tests {
		t.Run(tt.v1+"_vs_"+tt.v2, func(t *testing.T) {
			got, err := ComparePEP440(tt.v1, tt.v2)
			if err != nil {
				t.Errorf("ComparePEP440(%q, %q) error = %v", tt.v1, tt.v2, err)
				return
			}
			if got != tt.want {
				t.Errorf("ComparePEP440(%q, %q) = %d, want %d", tt.v1, tt.v2, got, tt.want)
			}
		})
	}
}

func TestCompareDebian(t *testing.T) {
	tests := []struct {
		v1, v2 string
		want   int
	}{
		// Basic comparisons
		{"1.0", "2.0", -1},
		{"2.0", "1.0", 1},
		{"1.0", "1.0", 0},

		// Epochs
		{"1:1.0", "2.0", 1},    // epoch 1 > no epoch
		{"2:1.0", "1:2.0", 1},  // higher epoch wins
		{"1:1.0", "1:2.0", -1}, // same epoch, compare versions

		// Tilde handling (critical!)
		{"1.0~rc1", "1.0", -1},     // tilde sorts before empty
		{"1.0~alpha", "1.0~beta", -1},
		{"1.0~1", "1.0~2", -1},

		// Debian revision
		{"1.0-1", "1.0-2", -1},
		{"1.0-1", "1.0", 1}, // Revision 1 > no revision (no revision = empty string)

		// Security updates
		{"38.0.4-3+deb12u1", "38.0.4-3", 1},
		{"3.3.2-1+deb11u1", "3.3.2-1", 1},

		// Numeric vs string in non-digit portion
		{"1.8.5-7.el8_10", "1.8.5-7.el8_6", 1}, // 10 > 6

		// Complex real-world
		{"1:1.8.5-7.el8", "1.8.5-7.el8", 1}, // epoch wins
	}

	for _, tt := range tests {
		t.Run(tt.v1+"_vs_"+tt.v2, func(t *testing.T) {
			got, err := CompareDebian(tt.v1, tt.v2)
			if err != nil {
				t.Errorf("CompareDebian(%q, %q) error = %v", tt.v1, tt.v2, err)
				return
			}
			if got != tt.want {
				t.Errorf("CompareDebian(%q, %q) = %d, want %d", tt.v1, tt.v2, got, tt.want)
			}
		})
	}
}

func TestCompareRPM(t *testing.T) {
	tests := []struct {
		v1, v2 string
		want   int
	}{
		// Basic comparisons
		{"1.0", "2.0", -1},
		{"2.0", "1.0", 1},
		{"1.0", "1.0", 0},

		// Epochs
		{"1:1.0", "2.0", 1},    // epoch 1 > no epoch
		{"1:1.0", "1:2.0", -1}, // same epoch

		// Release comparisons
		{"1.2.3-4.el8", "1.2.3-5.el8", -1},
		{"2.4.6-97.el7", "2.4.6-98.el7", -1},

		// Numeric suffix handling (underscore acts as delimiter)
		{"1.8.5-7.el8_10", "1.8.5-7.el8_6", 1}, // 10 > 6
		{"1.8.5-7.el8_2", "1.8.5-7.el8_10", -1}, // 2 < 10

		// Distro suffixes
		{"1.0-1.fc38", "1.0-1.fc39", -1},
		{"1.0-1.el8", "1.0-1.el9", -1},

		// Additional underscore tests
		{"1.0_rc1", "1.0_rc2", -1},   // rc1 < rc2
		{"1.0_beta", "1.0_rc", -1},   // beta < rc (lexicographic for alpha)
	}

	for _, tt := range tests {
		t.Run(tt.v1+"_vs_"+tt.v2, func(t *testing.T) {
			got, err := CompareRPM(tt.v1, tt.v2)
			if err != nil {
				t.Errorf("CompareRPM(%q, %q) error = %v", tt.v1, tt.v2, err)
				return
			}
			if got != tt.want {
				t.Errorf("CompareRPM(%q, %q) = %d, want %d", tt.v1, tt.v2, got, tt.want)
			}
		})
	}
}

func TestCompareAlpine(t *testing.T) {
	tests := []struct {
		v1, v2 string
		want   int
	}{
		// Basic comparisons
		{"1.0", "2.0", -1},
		{"2.0", "1.0", 1},
		{"1.0", "1.0", 0},

		// Revision comparisons
		{"2.4.62-r0", "2.4.62-r1", -1},
		{"2.4.62-r5", "2.4.62-r10", -1},
		{"2.4.61-r5", "2.4.62-r0", -1}, // base version wins

		// Without revision
		{"1.0.0", "1.0.0-r0", 0}, // should be equal (no revision = r0)
	}

	for _, tt := range tests {
		t.Run(tt.v1+"_vs_"+tt.v2, func(t *testing.T) {
			got, err := CompareAlpine(tt.v1, tt.v2)
			if err != nil {
				t.Errorf("CompareAlpine(%q, %q) error = %v", tt.v1, tt.v2, err)
				return
			}
			if got != tt.want {
				t.Errorf("CompareAlpine(%q, %q) = %d, want %d", tt.v1, tt.v2, got, tt.want)
			}
		})
	}
}

func TestCompareMaven(t *testing.T) {
	tests := []struct {
		v1, v2 string
		want   int
	}{
		// Basic comparisons
		{"1.0.0", "2.0.0", -1},
		{"2.0.0", "1.0.0", 1},
		{"1.0.0", "1.0.0", 0},

		// Qualifier ordering
		{"1.0.0-SNAPSHOT", "1.0.0", -1},
		{"1.0.0-RELEASE", "1.0.0", -1},
		{"1.0.0-FINAL", "1.0.0", -1},
		{"1.0.0-GA", "1.0.0", -1},

		// RELEASE == FINAL == GA
		{"1.0.0-RELEASE", "1.0.0-FINAL", 0},
		{"1.0.0-RELEASE", "1.0.0-GA", 0},

		// Alpha/Beta ordering
		{"1.0.0-alpha", "1.0.0-beta", -1},
		{"1.0.0-beta", "1.0.0-rc", -1},

		// Real-world: log4j
		{"2.14.1", "2.15.0", -1},
	}

	for _, tt := range tests {
		t.Run(tt.v1+"_vs_"+tt.v2, func(t *testing.T) {
			got, err := CompareMaven(tt.v1, tt.v2)
			if err != nil {
				t.Errorf("CompareMaven(%q, %q) error = %v", tt.v1, tt.v2, err)
				return
			}
			if got != tt.want {
				t.Errorf("CompareMaven(%q, %q) = %d, want %d", tt.v1, tt.v2, got, tt.want)
			}
		})
	}
}

func TestCompareGeneric(t *testing.T) {
	tests := []struct {
		v1, v2 string
		want   int
	}{
		// Numeric comparison
		{"1.10.0", "1.9.0", 1},   // 10 > 9 (not string comparison)
		{"10.0.0", "9.0.0", 1},   // 10 > 9
		{"1.2.3", "1.2.3", 0},

		// v prefix
		{"v1.0.0", "1.0.0", 0},

		// Whitespace
		{" 1.0.0 ", "1.0.0", 0},
	}

	for _, tt := range tests {
		t.Run(tt.v1+"_vs_"+tt.v2, func(t *testing.T) {
			got, err := CompareGeneric(tt.v1, tt.v2)
			if err != nil {
				t.Errorf("CompareGeneric(%q, %q) error = %v", tt.v1, tt.v2, err)
				return
			}
			if got != tt.want {
				t.Errorf("CompareGeneric(%q, %q) = %d, want %d", tt.v1, tt.v2, got, tt.want)
			}
		})
	}
}

func TestDetectFormat(t *testing.T) {
	tests := []struct {
		version string
		hint    string
		want    Format
	}{
		// Hint takes precedence
		{"1.0.0", "npm", SemverFormat},
		{"1.0.0", "pypi", PEP440Format},
		{"1.0.0", "rpm", RpmFormat},

		// RPM patterns
		{"1:1.8.5", "", RpmFormat},           // epoch
		{"1.8.5-7.el8", "", RpmFormat},       // .el suffix
		{"1.8.5-7.fc38", "", RpmFormat},      // .fc suffix
		{"1.8.5-1.amzn2023", "", RpmFormat},  // .amzn suffix

		// Debian patterns
		{"1.0-1+deb12u1", "", DebFormat},
		{"1.0~deb11u1", "", DebFormat},
		{"1.0-1ubuntu1", "", DebFormat},

		// Alpine pattern
		{"2.4.62-r0", "", ApkFormat},
		{"1.0.0-r5", "", ApkFormat},

		// Maven patterns
		{"1.0.0-SNAPSHOT", "", MavenFormat},
		{"1.0.0-RELEASE", "", MavenFormat},

		// Semver pattern
		{"1.0.0", "", SemverFormat},
		{"1.0.0-beta.1", "", SemverFormat},
		{"v1.0.0", "", SemverFormat},
	}

	for _, tt := range tests {
		t.Run(tt.version+"_hint_"+tt.hint, func(t *testing.T) {
			got := DetectFormat(tt.version, tt.hint)
			if got != tt.want {
				t.Errorf("DetectFormat(%q, %q) = %v, want %v", tt.version, tt.hint, got, tt.want)
			}
		})
	}
}

func TestVersionsComparable(t *testing.T) {
	tests := []struct {
		v1, v2    string
		ecosystem string
		want      bool
	}{
		// Both upstream - comparable
		{"1.0.0", "2.0.0", "npm", true},
		{"41.0.0", "42.0.0", "pypi", true},

		// Both distro - comparable
		{"1.0-1+deb11u1", "1.0-1+deb11u2", "deb", true},
		{"1.0-1.el8", "1.0-2.el8", "rpm", true},

		// Mixed - not comparable
		{"3.3.2-1+deb11u1", "41.0.0", "pypi", false},
		{"1.0-1.el8", "1.0.0", "rpm", false},
	}

	for _, tt := range tests {
		t.Run(tt.v1+"_vs_"+tt.v2, func(t *testing.T) {
			got := VersionsComparable(tt.v1, tt.v2, tt.ecosystem)
			if got != tt.want {
				t.Errorf("VersionsComparable(%q, %q, %q) = %v, want %v", tt.v1, tt.v2, tt.ecosystem, got, tt.want)
			}
		})
	}
}

func TestCheckVulnerabilityStatus(t *testing.T) {
	tests := []struct {
		name         string
		current      string
		introduced   string
		fixed        string
		lastAffected string
		format       Format
		wantStatus   VulnerabilityStatus
	}{
		{
			name:       "before introduced",
			current:    "0.9.0",
			introduced: "1.0.0",
			fixed:      "2.0.0",
			format:     SemverFormat,
			wantStatus: StatusNotAffected,
		},
		{
			name:       "at fix version",
			current:    "2.0.0",
			introduced: "1.0.0",
			fixed:      "2.0.0",
			format:     SemverFormat,
			wantStatus: StatusFixed,
		},
		{
			name:       "after fix version",
			current:    "3.0.0",
			introduced: "1.0.0",
			fixed:      "2.0.0",
			format:     SemverFormat,
			wantStatus: StatusFixed,
		},
		{
			name:       "in vulnerable range",
			current:    "1.5.0",
			introduced: "1.0.0",
			fixed:      "2.0.0",
			format:     SemverFormat,
			wantStatus: StatusVulnerable,
		},
		{
			name:       "at introduced version",
			current:    "1.0.0",
			introduced: "1.0.0",
			fixed:      "2.0.0",
			format:     SemverFormat,
			wantStatus: StatusVulnerable,
		},
		{
			name:       "no fix available",
			current:    "1.5.0",
			introduced: "1.0.0",
			fixed:      "",
			format:     SemverFormat,
			wantStatus: StatusVulnerable,
		},
		{
			name:         "past last affected",
			current:      "3.0.0",
			introduced:   "1.0.0",
			lastAffected: "2.0.0",
			format:       SemverFormat,
			wantStatus:   StatusNotAffected,
		},
		{
			name:       "empty introduced means from start",
			current:    "0.5.0",
			introduced: "",
			fixed:      "1.0.0",
			format:     SemverFormat,
			wantStatus: StatusVulnerable,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status, msg := CheckVulnerabilityStatus(tt.current, tt.introduced, tt.fixed, tt.lastAffected, tt.format)
			if status != tt.wantStatus {
				t.Errorf("CheckVulnerabilityStatus() status = %v, want %v, msg = %s", status, tt.wantStatus, msg)
			}
		})
	}
}

func TestInRange(t *testing.T) {
	tests := []struct {
		name       string
		version    string
		introduced string
		fixed      string
		format     Format
		want       bool
	}{
		{"before range", "0.5.0", "1.0.0", "2.0.0", SemverFormat, false},
		{"at lower bound", "1.0.0", "1.0.0", "2.0.0", SemverFormat, true},
		{"in range", "1.5.0", "1.0.0", "2.0.0", SemverFormat, true},
		{"at upper bound", "2.0.0", "1.0.0", "2.0.0", SemverFormat, false},
		{"after range", "3.0.0", "1.0.0", "2.0.0", SemverFormat, false},
		{"no upper bound", "5.0.0", "1.0.0", "", SemverFormat, true},
		{"empty introduced", "0.5.0", "", "1.0.0", SemverFormat, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := InRange(tt.version, tt.introduced, tt.fixed, tt.format)
			if err != nil {
				t.Errorf("InRange() error = %v", err)
				return
			}
			if got != tt.want {
				t.Errorf("InRange(%q, %q, %q) = %v, want %v", tt.version, tt.introduced, tt.fixed, got, tt.want)
			}
		})
	}
}

func TestIsZeroVersion(t *testing.T) {
	tests := []struct {
		version string
		want    bool
	}{
		{"0", true},
		{"0.0", true},
		{"0.0.0", true},
		{"0.0.0.0", true},
		{"", true},
		{"0.1", false},
		{"0.0.1", false},
		{"1.0.0", false},
	}

	for _, tt := range tests {
		t.Run(tt.version, func(t *testing.T) {
			got := isZeroVersion(tt.version)
			if got != tt.want {
				t.Errorf("isZeroVersion(%q) = %v, want %v", tt.version, got, tt.want)
			}
		})
	}
}

func TestEpochOverflowSafety(t *testing.T) {
	// Test that epoch parsing handles overflow and invalid values safely

	t.Run("Debian with huge epoch", func(t *testing.T) {
		// 9999999999999999999 is larger than int64 max
		v1 := NewDebianVersion("9999999999999999999:1.0")
		v2 := NewDebianVersion("1:1.0")
		// Invalid epoch defaults to 0, so v2 (epoch 1) should be greater
		result := v1.Compare(v2)
		if result != -1 {
			t.Errorf("Expected epoch overflow to default to 0, got comparison result: %d", result)
		}
	})

	t.Run("Debian with negative epoch string", func(t *testing.T) {
		v1 := NewDebianVersion("-1:1.0")
		v2 := NewDebianVersion("0:1.0")
		// Negative epoch should be treated as invalid, defaulting to 0
		// Both should have epoch 0, so compare upstream versions
		result := v1.Compare(v2)
		if result != 0 {
			t.Errorf("Expected negative epoch to default to 0, got comparison result: %d", result)
		}
	})

	t.Run("RPM with huge epoch", func(t *testing.T) {
		v1 := NewRPMVersion("9999999999999999999:1.0-1")
		v2 := NewRPMVersion("1:1.0-1")
		// Invalid epoch defaults to 0
		result := v1.Compare(v2)
		if result != -1 {
			t.Errorf("Expected epoch overflow to default to 0, got comparison result: %d", result)
		}
	})

	t.Run("Alpine with huge revision", func(t *testing.T) {
		v1 := NewAlpineVersion("1.0.0-r9999999999999999999")
		v2 := NewAlpineVersion("1.0.0-r1")
		// Invalid revision defaults to 0
		result := v1.Compare(v2)
		if result != -1 {
			t.Errorf("Expected revision overflow to default to 0, got comparison result: %d", result)
		}
	})
}

// TestVersionEdgeCases covers many edge cases across all version formats.
func TestVersionEdgeCases(t *testing.T) {
	t.Run("Semver Edge Cases", func(t *testing.T) {
		tests := []struct {
			v1, v2 string
			want   int
		}{
			// Numeric prerelease ordering
			{"1.0.0-0", "1.0.0-1", -1},
			{"1.0.0-10", "1.0.0-9", 1},
			// Metadata ignored
			{"1.0.0+build.123", "1.0.0+build.456", 0},
			{"1.0.0-alpha+build", "1.0.0-alpha", 0},
			// Long prerelease
			{"1.0.0-alpha.beta.gamma.delta", "1.0.0-alpha.beta.gamma.epsilon", -1},
			// Prerelease with numbers
			{"1.0.0-alpha.1.2.3", "1.0.0-alpha.1.2.4", -1},
			// Extreme versions
			{"0.0.0", "0.0.1", -1},
			{"999.999.999", "1000.0.0", -1},
		}

		for _, tt := range tests {
			got, _ := CompareSemver(tt.v1, tt.v2)
			if got != tt.want {
				t.Errorf("CompareSemver(%q, %q) = %d, want %d", tt.v1, tt.v2, got, tt.want)
			}
		}
	})

	t.Run("PEP440 Edge Cases", func(t *testing.T) {
		tests := []struct {
			v1, v2 string
			want   int
		}{
			// Zero epoch
			{"0!1.0.0", "1.0.0", 0},
			// Dev versions
			{"1.0.0.dev0", "1.0.0.dev1", -1},
			{"1.0.0.dev", "1.0.0a0", -1},
			// Alpha without number
			{"1.0.0a", "1.0.0a1", -1},
			// Local version stripped
			{"1.0.0+local", "1.0.0+other", 0},
			// Multiple levels
			{"1.0.0.0.0", "1.0.0.0.1", -1},
		}

		for _, tt := range tests {
			got, _ := ComparePEP440(tt.v1, tt.v2)
			if got != tt.want {
				t.Errorf("ComparePEP440(%q, %q) = %d, want %d", tt.v1, tt.v2, got, tt.want)
			}
		}
	})

	t.Run("Debian Edge Cases", func(t *testing.T) {
		tests := []struct {
			v1, v2 string
			want   int
		}{
			// Multiple tildes
			{"1.0~~", "1.0~", -1},
			{"1.0~a~b", "1.0~a~c", -1},
			// Empty string handling
			{"", "", 0},
			{"1.0", "", 1},
			// Complex revisions
			{"1.0-1~bpo11+1", "1.0-1~bpo11+2", -1},
			// Letters vs numbers
			{"1.0a", "1.01", -1}, // letters after non-letters
			// Epoch edge cases
			{"0:1.0", "1.0", 0}, // 0 epoch equals no epoch
		}

		for _, tt := range tests {
			got, _ := CompareDebian(tt.v1, tt.v2)
			if got != tt.want {
				t.Errorf("CompareDebian(%q, %q) = %d, want %d", tt.v1, tt.v2, got, tt.want)
			}
		}
	})

	t.Run("Alpine Edge Cases", func(t *testing.T) {
		tests := []struct {
			v1, v2 string
			want   int
		}{
			// Implicit revision
			{"1.0", "1.0-r0", 0},
			// Large revision numbers
			{"1.0-r99", "1.0-r100", -1},
			// No revision pattern match
			{"1.0-release", "1.0-r0", 1}, // -release is not -rN
		}

		for _, tt := range tests {
			got, _ := CompareAlpine(tt.v1, tt.v2)
			if got != tt.want {
				t.Errorf("CompareAlpine(%q, %q) = %d, want %d", tt.v1, tt.v2, got, tt.want)
			}
		}
	})

	t.Run("Maven Edge Cases", func(t *testing.T) {
		tests := []struct {
			v1, v2 string
			want   int
		}{
			// Qualifier ordering
			{"1.0-alpha", "1.0-beta", -1},
			{"1.0-beta", "1.0-rc", -1},
			{"1.0-SNAPSHOT", "1.0-alpha", -1},
			{"1.0-rc", "1.0-RELEASE", -1},
			// Same qualifier type means equal
			{"1.0-rc", "1.0-cr", 0}, // rc == cr
			// Base version comparison
			{"1.0-RELEASE", "2.0-RELEASE", -1},
		}

		for _, tt := range tests {
			got, _ := CompareMaven(tt.v1, tt.v2)
			if got != tt.want {
				t.Errorf("CompareMaven(%q, %q) = %d, want %d", tt.v1, tt.v2, got, tt.want)
			}
		}
	})

	t.Run("Generic Edge Cases", func(t *testing.T) {
		tests := []struct {
			v1, v2 string
			want   int
		}{
			// Mixed delimiters treated equally
			{"1.0.0", "1-0-0", 0},
			// Very long versions
			{"1.0.0.0.0.0.0.0.0.0", "1.0.0.0.0.0.0.0.0.1", -1},
			// Numeric comparison works correctly
			{"1.10.0", "1.9.0", 1},
			{"10.0.0", "9.0.0", 1},
			// Same versions
			{"1.2.3", "1.2.3", 0},
		}

		for _, tt := range tests {
			got, _ := CompareGeneric(tt.v1, tt.v2)
			if got != tt.want {
				t.Errorf("CompareGeneric(%q, %q) = %d, want %d", tt.v1, tt.v2, got, tt.want)
			}
		}
	})
}

// TestWhitespaceHandling ensures whitespace is handled correctly.
func TestWhitespaceHandling(t *testing.T) {
	tests := []struct {
		format string
		v1, v2 string
		want   int
	}{
		{"semver", " 1.0.0 ", "1.0.0", 0},
		{"semver", "\t1.0.0\n", "1.0.0", 0},
		{"pep440", " 1.0.0 ", "1.0.0", 0},
		{"debian", " 1.0-1 ", "1.0-1", 0},
		{"rpm", " 1.0 ", "1.0", 0},
		{"alpine", " 1.0-r0 ", "1.0-r0", 0},
		{"maven", " 1.0.0 ", "1.0.0", 0},
	}

	for _, tt := range tests {
		t.Run(tt.format, func(t *testing.T) {
			var got int
			switch tt.format {
			case "semver":
				got, _ = CompareSemver(tt.v1, tt.v2)
			case "pep440":
				got, _ = ComparePEP440(tt.v1, tt.v2)
			case "debian":
				got, _ = CompareDebian(tt.v1, tt.v2)
			case "rpm":
				got, _ = CompareRPM(tt.v1, tt.v2)
			case "alpine":
				got, _ = CompareAlpine(tt.v1, tt.v2)
			case "maven":
				got, _ = CompareMaven(tt.v1, tt.v2)
			}
			if got != tt.want {
				t.Errorf("%s: Compare(%q, %q) = %d, want %d", tt.format, tt.v1, tt.v2, got, tt.want)
			}
		})
	}
}

// TestFormatDetectionEdgeCases tests edge cases in format detection.
func TestFormatDetectionEdgeCases(t *testing.T) {
	tests := []struct {
		version string
		hint    string
		want    Format
	}{
		// Ambiguous versions - "1.0.0" is semver, shorter ones are generic
		{"1.0.0", "", SemverFormat}, // 3 parts -> semver
		{"1.0", "", GenericFormat},  // 2 parts -> generic
		{"1", "", GenericFormat},    // 1 part -> generic

		// Case insensitive hints
		{"1.0.0", "NPM", SemverFormat},
		{"1.0.0", "PyPi", PEP440Format},
		{"1.0.0", "PYPI", PEP440Format},

		// Unknown hints fall back to pattern detection
		{"1.0.0-r0", "unknown", ApkFormat},
		{"1.0-1.el8", "unknown", RpmFormat},
	}

	for _, tt := range tests {
		t.Run(tt.version+"_"+tt.hint, func(t *testing.T) {
			got := DetectFormat(tt.version, tt.hint)
			if got != tt.want {
				t.Errorf("DetectFormat(%q, %q) = %v, want %v", tt.version, tt.hint, got, tt.want)
			}
		})
	}
}

// TestCompareWithFormat tests the unified Compare function.
func TestCompareWithFormat(t *testing.T) {
	tests := []struct {
		v1, v2 string
		format Format
		want   int
	}{
		{"1.0.0", "2.0.0", SemverFormat, -1},
		{"1.0.0", "1.0.0", SemverFormat, 0},
		{"2.0.0", "1.0.0", SemverFormat, 1},
		{"1.0.0", "2.0.0", PEP440Format, -1},
		{"1.0-1", "1.0-2", DebFormat, -1},
		{"1.0-1.el8", "1.0-2.el8", RpmFormat, -1},
		{"1.0-r0", "1.0-r1", ApkFormat, -1},
		{"1.0.0-SNAPSHOT", "1.0.0", MavenFormat, -1},
	}

	for _, tt := range tests {
		t.Run(tt.format.String(), func(t *testing.T) {
			got, err := Compare(tt.v1, tt.v2, tt.format)
			if err != nil {
				t.Errorf("Compare(%q, %q, %v) error = %v", tt.v1, tt.v2, tt.format, err)
				return
			}
			if got != tt.want {
				t.Errorf("Compare(%q, %q, %v) = %d, want %d", tt.v1, tt.v2, tt.format, got, tt.want)
			}
		})
	}
}

// TestVulnerabilityStatusEdgeCases tests edge cases in vulnerability checking.
func TestVulnerabilityStatusEdgeCases(t *testing.T) {
	tests := []struct {
		name         string
		current      string
		introduced   string
		fixed        string
		lastAffected string
		format       Format
		wantStatus   VulnerabilityStatus
	}{
		{
			name:       "all empty strings",
			current:    "1.0.0",
			introduced: "",
			fixed:      "",
			format:     SemverFormat,
			wantStatus: StatusVulnerable,
		},
		{
			name:       "current equals fixed",
			current:    "2.0.0",
			introduced: "1.0.0",
			fixed:      "2.0.0",
			format:     SemverFormat,
			wantStatus: StatusFixed,
		},
		{
			name:       "current equals introduced",
			current:    "1.0.0",
			introduced: "1.0.0",
			fixed:      "2.0.0",
			format:     SemverFormat,
			wantStatus: StatusVulnerable,
		},
		{
			name:         "lastAffected less than current",
			current:      "2.0.0",
			introduced:   "1.0.0",
			lastAffected: "1.5.0",
			format:       SemverFormat,
			wantStatus:   StatusNotAffected,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status, _ := CheckVulnerabilityStatus(tt.current, tt.introduced, tt.fixed, tt.lastAffected, tt.format)
			if status != tt.wantStatus {
				t.Errorf("CheckVulnerabilityStatus() = %v, want %v", status, tt.wantStatus)
			}
		})
	}
}

func TestCompareNilSafety(t *testing.T) {
	// Test that all Compare methods handle nil without panicking
	// Convention: non-nil > nil (returns 1)

	t.Run("SemVer", func(t *testing.T) {
		v, err := NewSemVer("1.0.0")
		if err != nil {
			t.Fatalf("NewSemVer failed: %v", err)
		}
		result := v.Compare(nil)
		if result != 1 {
			t.Errorf("SemVer.Compare(nil) = %d, want 1", result)
		}
	})

	t.Run("PEP440", func(t *testing.T) {
		v, err := NewPEP440Version("1.0.0")
		if err != nil {
			t.Fatalf("NewPEP440Version failed: %v", err)
		}
		result := v.Compare(nil)
		if result != 1 {
			t.Errorf("PEP440Version.Compare(nil) = %d, want 1", result)
		}
	})

	t.Run("Debian", func(t *testing.T) {
		v := NewDebianVersion("1.0-1")
		result := v.Compare(nil)
		if result != 1 {
			t.Errorf("DebianVersion.Compare(nil) = %d, want 1", result)
		}
	})

	t.Run("RPM", func(t *testing.T) {
		v := NewRPMVersion("1.0-1.el8")
		result := v.Compare(nil)
		if result != 1 {
			t.Errorf("RPMVersion.Compare(nil) = %d, want 1", result)
		}
	})

	t.Run("Alpine", func(t *testing.T) {
		v := NewAlpineVersion("1.0.0-r0")
		result := v.Compare(nil)
		if result != 1 {
			t.Errorf("AlpineVersion.Compare(nil) = %d, want 1", result)
		}
	})

	t.Run("Maven", func(t *testing.T) {
		v := NewMavenVersion("1.0.0-RELEASE")
		result := v.Compare(nil)
		if result != 1 {
			t.Errorf("MavenVersion.Compare(nil) = %d, want 1", result)
		}
	})
}
