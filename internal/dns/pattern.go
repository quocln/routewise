// Package dns provides DNS resolution with caching and pattern matching.
package dns

import "strings"

// MatchDomain checks if domain matches a pattern.
// Patterns can be:
//   - Exact: "example.com"
//   - Wildcard label: "*.example.com"
//   - Partial label: "qa*.staging.example.com"
//
// A '*' matches within one label only, so "*.example.com" matches
// "api.example.com" but not "example.com" or "a.b.example.com". Matching
// ignores ASCII case and one trailing dot on either side. It runs on every
// forwarded query and captured connection, so it does not allocate for ASCII
// names.
func MatchDomain(domain, pattern string) bool {
	domain = strings.TrimSuffix(domain, ".")
	pattern = strings.TrimSuffix(pattern, ".")
	if !isASCII(domain) || !isASCII(pattern) {
		// Unicode case folding needs the full lowering; rare for DNS names.
		domain, pattern = strings.ToLower(domain), strings.ToLower(pattern)
	}
	return globMatch(domain, pattern)
}

// globMatch matches name against pattern, where '*' stands for any run of
// characters other than '.', comparing ASCII letters without case. Since '*'
// never crosses a dot, every dot in name must meet a literal dot in pattern.
// It is the classic linear wildcard match with one backtrack point.
func globMatch(name, pattern string) bool {
	n, p := 0, 0
	star, mark := -1, 0
	for n < len(name) {
		switch {
		case p < len(pattern) && pattern[p] == '*':
			star, mark = p, n
			p++
		case p < len(pattern) && foldEq(pattern[p], name[n]):
			n++
			p++
		case star >= 0 && name[mark] != '.':
			// Let the last '*' take one more character, never a dot.
			mark++
			n, p = mark, star+1
		default:
			return false
		}
	}
	for p < len(pattern) && pattern[p] == '*' {
		p++
	}
	return p == len(pattern)
}

func foldEq(a, b byte) bool {
	if a == b {
		return true
	}
	if 'A' <= a && a <= 'Z' {
		a += 'a' - 'A'
	}
	if 'A' <= b && b <= 'Z' {
		b += 'a' - 'A'
	}
	return a == b
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

// FindMatchingPatterns returns all patterns that match the given domain.
func FindMatchingPatterns(domain string, patterns []string) []string {
	var matched []string
	for _, p := range patterns {
		if MatchDomain(domain, p) {
			matched = append(matched, p)
		}
	}
	return matched
}

// ShouldRoute checks if a domain matches any of the configured patterns.
func ShouldRoute(domain string, patterns []string) bool {
	for _, p := range patterns {
		if MatchDomain(domain, p) {
			return true
		}
	}
	return false
}
