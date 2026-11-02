package dns

import "testing"

func TestMatchDomain(t *testing.T) {
	tests := []struct {
		name    string
		domain  string
		pattern string
		want    bool
	}{
		// Exact matches
		{"exact match", "example.com", "example.com", true},
		{"exact match case insensitive", "Example.Com", "example.com", true},
		{"exact no match", "other.com", "example.com", false},
		{"exact with trailing dot", "example.com.", "example.com", true},

		// Wildcard prefix (*.domain.com)
		{"wildcard prefix match", "sub.example.com", "*.example.com", true},
		{"wildcard prefix match www", "www.example.com", "*.example.com", true},
		{"wildcard prefix no match root", "example.com", "*.example.com", false},
		{"wildcard prefix no match nested", "a.b.example.com", "*.example.com", false},

		// Wildcard in middle (qa*.staging.example.com)
		{"wildcard middle match", "qa1.staging.example.com", "qa*.staging.example.com", true},
		{"wildcard middle match qa5", "qa5.staging.example.com", "qa*.staging.example.com", true},
		{"wildcard middle match qa100", "qa100.staging.example.com", "qa*.staging.example.com", true},
		{"wildcard middle no match", "prod.staging.example.com", "qa*.staging.example.com", false},
		{"wildcard middle no match qa.sub", "qa1.sub.staging.example.com", "qa*.staging.example.com", false},

		// Real-world patterns from config
		{"gateway exact", "api.internal.example.com", "api.internal.example.com", true},
		{"gateway exact 2", "gateway.staging.example.com", "gateway.staging.example.com", true},
		{"wildcard internal example", "www.internal.example.com", "*.internal.example.com", true},
		{"wildcard internal api", "api.internal.example.com", "*.internal.example.com", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := MatchDomain(tt.domain, tt.pattern)
			if got != tt.want {
				t.Errorf("MatchDomain(%q, %q) = %v, want %v",
					tt.domain, tt.pattern, got, tt.want)
			}
		})
	}
}

func TestFindMatchingPatterns(t *testing.T) {
	patterns := []string{
		"api.internal.example.com",
		"gateway.staging.example.com",
		"qa*.staging.example.com",
		"*.internal.example.com",
	}

	tests := []struct {
		name    string
		domain  string
		wantLen int
	}{
		{"exact match only", "api.internal.example.com", 2},
		{"qa subdomain", "qa1.staging.example.com", 1},
		{"wildcard internal", "www.internal.example.com", 1},
		{"no match", "google.com", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FindMatchingPatterns(tt.domain, patterns)
			if len(got) != tt.wantLen {
				t.Errorf("FindMatchingPatterns(%q) returned %d patterns, want %d",
					tt.domain, len(got), tt.wantLen)
			}
		})
	}
}

func TestShouldRoute(t *testing.T) {
	patterns := []string{
		"api.internal.example.com",
		"*.internal.example.com",
	}

	tests := []struct {
		domain string
		want   bool
	}{
		{"api.internal.example.com", true},
		{"www.internal.example.com", true},
		{"google.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.domain, func(t *testing.T) {
			got := ShouldRoute(tt.domain, patterns)
			if got != tt.want {
				t.Errorf("ShouldRoute(%q) = %v, want %v", tt.domain, got, tt.want)
			}
		})
	}
}
