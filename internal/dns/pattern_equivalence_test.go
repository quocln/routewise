package dns

import (
	"regexp"
	"strings"
	"testing"
)

// regexMatchDomain is the original regex-based matcher, kept as the oracle
// the allocation-free matcher must agree with.
func regexMatchDomain(domain, pattern string) bool {
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	pattern = strings.ToLower(strings.TrimSuffix(pattern, "."))
	if !strings.Contains(pattern, "*") {
		return domain == pattern
	}
	re, err := regexp.Compile(strings.ReplaceAll("^"+regexp.QuoteMeta(pattern)+"$", `\*`, `[^.]*`))
	if err != nil {
		return false
	}
	return re.MatchString(domain)
}

func TestMatchDomainAgreesWithTheRegexDefinition(t *testing.T) {
	names := []string{"", ".", "a", "example.com", "Example.COM.", "api.example.com", "a.b.example.com",
		"qa1.staging.example.com", "qa.staging.example.com", "xqa.staging.example.com", "a..b", "*.example.com",
		"aaa.bbb", "ab", "abab.c", "münchen.de", "MÜNCHEN.de"}
	patterns := []string{"", "*", "*.*", "example.com", "*.example.com", "qa*.staging.example.com",
		"*a*.bbb", "a*b", "*ab", "a**b", "*.de", "m*n.de", "M*.DE", "*.EXAMPLE.com.", "a.*.b"}
	for _, n := range names {
		for _, p := range patterns {
			if got, want := MatchDomain(n, p), regexMatchDomain(n, p); got != want {
				t.Errorf("MatchDomain(%q, %q) = %v, regex says %v", n, p, got, want)
			}
		}
	}
}

func FuzzMatchDomainAgreesWithTheRegexDefinition(f *testing.F) {
	f.Add("api.example.com", "*.example.com")
	f.Add("qa1.staging.example.com", "qa*.staging.example.com")
	f.Add("abab.c", "*ab*.c")
	f.Fuzz(func(t *testing.T, name, pattern string) {
		if !isASCII(name) || !isASCII(pattern) {
			t.Skip() // the oracle and the matcher fold Unicode the same way, but regexp treats invalid UTF-8 differently
		}
		if got, want := MatchDomain(name, pattern), regexMatchDomain(name, pattern); got != want {
			t.Errorf("MatchDomain(%q, %q) = %v, regex says %v", name, pattern, got, want)
		}
	})
}

func BenchmarkMatchDomainWildcard(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		MatchDomain("api.corp.example.com", "*.corp.example.com")
	}
}
