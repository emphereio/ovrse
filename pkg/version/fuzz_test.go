package version

import (
	"testing"
)

// Fuzz tests for version comparison functions.
// These ensure no panics occur with arbitrary input.

func FuzzCompareSemver(f *testing.F) {
	// Add seed corpus
	seeds := []string{
		"1.0.0", "2.0.0", "v1.0.0", "1.0.0-alpha", "1.0.0-beta.1",
		"1.0.0+build", "1.0.0-rc.1+build.123", "", "invalid",
		"0.0.0", "999.999.999", "1.0.0-alpha.1.beta.2",
	}
	for _, s := range seeds {
		f.Add(s, s)
	}

	f.Fuzz(func(t *testing.T, v1, v2 string) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("panic with inputs %q, %q: %v", v1, v2, r)
			}
		}()
		// Should not panic
		_, _ = CompareSemver(v1, v2)
	})
}

func FuzzComparePEP440(f *testing.F) {
	seeds := []string{
		"1.0.0", "2.0.0", "1.0.0a1", "1.0.0b1", "1.0.0rc1",
		"1.0.0.post1", "1.0.0.dev1", "1!1.0.0", "1.0.0+local",
		"", "invalid", "0", "1.0.0.0.0.0",
	}
	for _, s := range seeds {
		f.Add(s, s)
	}

	f.Fuzz(func(t *testing.T, v1, v2 string) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("panic with inputs %q, %q: %v", v1, v2, r)
			}
		}()
		_, _ = ComparePEP440(v1, v2)
	})
}

func FuzzCompareDebian(f *testing.F) {
	seeds := []string{
		"1.0", "2.0", "1:1.0", "1.0-1", "1.0~rc1", "1.0+deb12u1",
		"1:2.3.4-5+deb12u1", "", "invalid", "999:999.999-999",
		"1.0~", "~1.0", "1.0~~rc", "::::",
	}
	for _, s := range seeds {
		f.Add(s, s)
	}

	f.Fuzz(func(t *testing.T, v1, v2 string) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("panic with inputs %q, %q: %v", v1, v2, r)
			}
		}()
		_, _ = CompareDebian(v1, v2)
	})
}

func FuzzCompareRPM(f *testing.F) {
	seeds := []string{
		"1.0", "2.0", "1:1.0", "1.0-1.el8", "1.0-1.fc38",
		"1.8.5-7.el8_10", "", "invalid", "1.0-1.amzn2023",
		"999:999.999-999", "----", "....",
	}
	for _, s := range seeds {
		f.Add(s, s)
	}

	f.Fuzz(func(t *testing.T, v1, v2 string) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("panic with inputs %q, %q: %v", v1, v2, r)
			}
		}()
		_, _ = CompareRPM(v1, v2)
	})
}

func FuzzCompareAlpine(f *testing.F) {
	seeds := []string{
		"1.0", "2.0", "1.0.0-r0", "2.4.62-r5", "1.0-r999",
		"", "invalid", "1.0-r", "-r0", "1.0-r-1",
	}
	for _, s := range seeds {
		f.Add(s, s)
	}

	f.Fuzz(func(t *testing.T, v1, v2 string) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("panic with inputs %q, %q: %v", v1, v2, r)
			}
		}()
		_, _ = CompareAlpine(v1, v2)
	})
}

func FuzzCompareMaven(f *testing.F) {
	seeds := []string{
		"1.0.0", "2.0.0", "1.0.0-SNAPSHOT", "1.0.0-RELEASE",
		"1.0.0-FINAL", "1.0.0-GA", "1.0.0-alpha", "1.0.0-beta",
		"", "invalid", "1.0.0-rc1", "1.0.0-sp1",
	}
	for _, s := range seeds {
		f.Add(s, s)
	}

	f.Fuzz(func(t *testing.T, v1, v2 string) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("panic with inputs %q, %q: %v", v1, v2, r)
			}
		}()
		_, _ = CompareMaven(v1, v2)
	})
}

func FuzzCompareGeneric(f *testing.F) {
	seeds := []string{
		"1.0.0", "2.0.0", "v1.0.0", "1.0.0.0.0", "",
		"invalid", "abc", "123", "a1b2c3", "....",
	}
	for _, s := range seeds {
		f.Add(s, s)
	}

	f.Fuzz(func(t *testing.T, v1, v2 string) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("panic with inputs %q, %q: %v", v1, v2, r)
			}
		}()
		_, _ = CompareGeneric(v1, v2)
	})
}

func FuzzDetectFormat(f *testing.F) {
	seeds := []string{
		"1.0.0", "v1.0.0", "1:1.0", "1.0-r0", "1.0-SNAPSHOT",
		"1.0.0a1", "1.0-1+deb12u1", "1.0-1.el8", "",
	}
	for _, s := range seeds {
		f.Add(s, "")
		f.Add(s, "npm")
		f.Add(s, "pypi")
	}

	f.Fuzz(func(t *testing.T, version, hint string) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("panic with inputs %q, %q: %v", version, hint, r)
			}
		}()
		DetectFormat(version, hint)
	})
}

func FuzzCompare(f *testing.F) {
	seeds := []string{
		"1.0.0", "2.0.0", "v1.0.0", "1:1.0", "1.0-r0",
		"1.0-SNAPSHOT", "1.0.0a1", "",
	}
	formats := []Format{
		SemverFormat, PEP440Format, DebFormat, RpmFormat,
		ApkFormat, MavenFormat, GenericFormat,
	}
	for _, s := range seeds {
		for _, fmt := range formats {
			f.Add(s, s, int(fmt))
		}
	}

	f.Fuzz(func(t *testing.T, v1, v2 string, formatInt int) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("panic with inputs %q, %q, %d: %v", v1, v2, formatInt, r)
			}
		}()
		// Constrain format to valid range
		format := Format(formatInt % 8) // 7 formats + unknown
		_, _ = Compare(v1, v2, format)
	})
}
