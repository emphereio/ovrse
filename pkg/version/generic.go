package version

import (
	"strconv"
	"strings"
	"unicode"
)

// CompareGeneric performs a loose version comparison that works for most formats.
// It splits versions on common delimiters and compares segments numerically when possible.
func CompareGeneric(v1, v2 string) (int, error) {
	v1 = normalizeVersion(v1)
	v2 = normalizeVersion(v2)

	if v1 == v2 {
		return 0, nil
	}

	tokens1 := tokenize(v1)
	tokens2 := tokenize(v2)

	maxLen := len(tokens1)
	if len(tokens2) > maxLen {
		maxLen = len(tokens2)
	}

	for i := 0; i < maxLen; i++ {
		var t1, t2 token
		if i < len(tokens1) {
			t1 = tokens1[i]
		}
		if i < len(tokens2) {
			t2 = tokens2[i]
		}

		cmp := compareTokens(t1, t2)
		if cmp != 0 {
			return cmp, nil
		}
	}

	return 0, nil
}

// token represents a version segment.
type token struct {
	isNum bool
	num   int64
	str   string
}

// tokenize splits a version string into comparable tokens.
func tokenize(v string) []token {
	var tokens []token
	var current strings.Builder
	var isNum bool
	var first = true

	for _, r := range v {
		// Skip delimiters
		if r == '.' || r == '-' || r == '_' || r == '+' {
			if current.Len() > 0 {
				tokens = append(tokens, makeToken(current.String(), isNum))
				current.Reset()
				first = true
			}
			continue
		}

		// Determine if this is a digit
		digit := unicode.IsDigit(r)

		if first {
			isNum = digit
			first = false
		} else if digit != isNum {
			// Type changed, emit current token
			if current.Len() > 0 {
				tokens = append(tokens, makeToken(current.String(), isNum))
				current.Reset()
			}
			isNum = digit
		}

		current.WriteRune(r)
	}

	// Emit final token
	if current.Len() > 0 {
		tokens = append(tokens, makeToken(current.String(), isNum))
	}

	return tokens
}

func makeToken(s string, isNum bool) token {
	if isNum {
		n, _ := strconv.ParseInt(s, 10, 64)
		return token{isNum: true, num: n, str: s}
	}
	return token{isNum: false, str: strings.ToLower(s)}
}

// compareTokens compares two tokens.
func compareTokens(t1, t2 token) int {
	// Both empty
	if t1.str == "" && t2.str == "" {
		return 0
	}

	// Empty vs non-empty: empty is less
	if t1.str == "" {
		return -1
	}
	if t2.str == "" {
		return 1
	}

	// Both numeric
	if t1.isNum && t2.isNum {
		if t1.num < t2.num {
			return -1
		}
		if t1.num > t2.num {
			return 1
		}
		return 0
	}

	// Numeric vs string: numeric comes first
	if t1.isNum && !t2.isNum {
		return -1
	}
	if !t1.isNum && t2.isNum {
		return 1
	}

	// Both strings: lexicographic comparison
	if t1.str < t2.str {
		return -1
	}
	if t1.str > t2.str {
		return 1
	}
	return 0
}

// normalizeVersion cleans up a version string for comparison.
func normalizeVersion(v string) string {
	v = strings.TrimSpace(v)
	v = strings.TrimPrefix(v, "v")
	v = strings.TrimPrefix(v, "V")
	return v
}

// GenericVersion represents a generic version string.
type GenericVersion struct {
	original string
}

// NewGenericVersion creates a new GenericVersion from a version string.
func NewGenericVersion(v string) *GenericVersion {
	return &GenericVersion{original: v}
}

// Compare implements Version.Compare.
func (g *GenericVersion) Compare(other Version) int {
	if other == nil {
		return 1 // non-nil > nil
	}
	cmp, _ := CompareGeneric(g.String(), other.String())
	return cmp
}

// String implements Version.String.
func (g *GenericVersion) String() string {
	return g.original
}

// Format implements Version.Format.
func (g *GenericVersion) Format() Format {
	return GenericFormat
}
