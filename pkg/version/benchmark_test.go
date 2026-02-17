package version

import (
	"testing"
)

// Benchmarks for version comparison functions.
// Run with: go test -bench=. -benchmem ./pkg/version/...

func BenchmarkCompareSemver(b *testing.B) {
	v1 := "1.0.0-alpha.1+build.123"
	v2 := "2.0.0-beta.2+build.456"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = CompareSemver(v1, v2)
	}
}

func BenchmarkCompareSemverEqual(b *testing.B) {
	v := "1.0.0"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = CompareSemver(v, v)
	}
}

func BenchmarkComparePEP440(b *testing.B) {
	v1 := "1.0.0a1.post1.dev1"
	v2 := "2.0.0b1.post2.dev2"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ComparePEP440(v1, v2)
	}
}

func BenchmarkCompareDebian(b *testing.B) {
	v1 := "1:2.3.4-5+deb12u1"
	v2 := "1:2.3.5-1+deb12u2"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = CompareDebian(v1, v2)
	}
}

func BenchmarkCompareDebianTilde(b *testing.B) {
	v1 := "1.0~alpha~1"
	v2 := "1.0~alpha~2"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = CompareDebian(v1, v2)
	}
}

func BenchmarkCompareRPM(b *testing.B) {
	v1 := "1:1.8.5-7.el8_10"
	v2 := "1:1.8.5-7.el8_6"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = CompareRPM(v1, v2)
	}
}

func BenchmarkCompareAlpine(b *testing.B) {
	v1 := "2.4.62-r5"
	v2 := "2.4.62-r10"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		CompareAlpine(v1, v2)
	}
}

func BenchmarkCompareMaven(b *testing.B) {
	v1 := "1.0.0-SNAPSHOT"
	v2 := "1.0.0-RELEASE"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		CompareMaven(v1, v2)
	}
}

func BenchmarkCompareGeneric(b *testing.B) {
	v1 := "1.2.3.4.5"
	v2 := "1.2.3.4.6"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		CompareGeneric(v1, v2)
	}
}

func BenchmarkDetectFormat(b *testing.B) {
	versions := []string{
		"1.0.0", "v1.0.0", "1:1.0.0", "1.0.0-r1",
		"1.0.0.el8", "1.0+deb12u1", "1.0.0-SNAPSHOT",
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		DetectFormat(versions[i%len(versions)], "")
	}
}

func BenchmarkDetectFormatWithHint(b *testing.B) {
	version := "1.0.0"
	hints := []string{"npm", "pypi", "go", "deb", "rpm", "apk", "maven"}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		DetectFormat(version, hints[i%len(hints)])
	}
}

func BenchmarkCompareUnified(b *testing.B) {
	v1 := "1.0.0"
	v2 := "2.0.0"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Compare(v1, v2, SemverFormat)
	}
}

func BenchmarkCheckVulnerabilityStatus(b *testing.B) {
	current := "1.5.0"
	introduced := "1.0.0"
	fixed := "2.0.0"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		CheckVulnerabilityStatus(current, introduced, fixed, "", SemverFormat)
	}
}

func BenchmarkInRange(b *testing.B) {
	version := "1.5.0"
	introduced := "1.0.0"
	fixed := "2.0.0"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		InRange(version, introduced, fixed, SemverFormat)
	}
}

// Benchmark long version strings
func BenchmarkCompareLongVersion(b *testing.B) {
	v1 := "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0"
	v2 := "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.1"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		CompareGeneric(v1, v2)
	}
}

// Benchmark version type construction
func BenchmarkNewSemVer(b *testing.B) {
	v := "1.0.0-alpha.1+build.123"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		NewSemVer(v)
	}
}

func BenchmarkNewDebianVersion(b *testing.B) {
	v := "1:2.3.4-5+deb12u1"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		NewDebianVersion(v)
	}
}

func BenchmarkNewRPMVersion(b *testing.B) {
	v := "1:1.8.5-7.el8_10"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		NewRPMVersion(v)
	}
}

func BenchmarkNewAlpineVersion(b *testing.B) {
	v := "2.4.62-r5"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		NewAlpineVersion(v)
	}
}

func BenchmarkNewMavenVersion(b *testing.B) {
	v := "1.0.0-SNAPSHOT"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		NewMavenVersion(v)
	}
}
