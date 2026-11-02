package config

import (
	"github.com/quocln/routewise/internal/testenv"
	"strings"
	"testing"
)

func TestParseEntryAcceptsAndNormalizes(t *testing.T) {
	cases := []struct {
		in   string
		kind EntryKind
		want string
	}{
		{"example.com", EntryDomain, "example.com"},
		{"*.example.com", EntryDomain, "*.example.com"},
		{"10.20.30.40", EntryIP, "10.20.30.40"},
		{"10.20.0.0/16", EntryCIDR, "10.20.0.0/16"},
		{"10.20.5.1/16", EntryCIDR, "10.20.0.0/16"},       // non-canonical: network address
		{"10.20.30.40/32", EntryIP, "10.20.30.40"},        // /32 is a plain IP
		{"10.20.30.41/31", EntryCIDR, "10.20.30.40/31"},   // /31 stays a network
		{"10.0.0.0/8", EntryCIDR, "10.0.0.0/8"},           // the shortest allowed
		{"192.168.1.77/24", EntryCIDR, "192.168.1.0/24"},  // host bits cleared
		{"223.255.255.255", EntryIP, "223.255.255.255"},   // last address below multicast
		{"126.255.255.255/9", EntryCIDR, "126.128.0.0/9"}, // next to loopback, not overlapping it
		{"169.253.0.0/16", EntryCIDR, "169.253.0.0/16"},   // next to link-local
	}
	for _, tc := range cases {
		e, err := ParseEntry(tc.in)
		if err != nil {
			t.Errorf("ParseEntry(%q): %v", tc.in, err)
			continue
		}
		if e.Kind != tc.kind || e.Value != tc.want {
			t.Errorf("ParseEntry(%q) = kind %v value %q, want kind %v value %q", tc.in, e.Kind, e.Value, tc.kind, tc.want)
		}
		if !IsValidEntry(tc.in) {
			t.Errorf("IsValidEntry(%q) = false", tc.in)
		}
	}
}

func TestParseEntryRejects(t *testing.T) {
	cases := []struct {
		in      string
		wantMsg string
	}{
		{"::1", "IPv6"},
		{"2001:db8::1", "IPv6"},
		{"2001:db8::/32", "IPv6"},
		{"::ffff:10.0.0.1", "IPv6"},
		{"10.0.0.0/7", "too broad"},
		{"0.0.0.0/0", "too broad"},
		{"128.0.0.0/1", "too broad"},
		{"0.0.0.0/8", "0.0.0.0/8"},
		{"0.0.0.1", "0.0.0.0/8"},
		{"127.0.0.1", "loopback"},
		{"127.5.0.0/16", "loopback"},
		{"224.0.0.0/4", "too broad"},
		{"224.0.0.0/8", "multicast"},
		{"239.1.1.1", "multicast"},
		{"255.255.255.255", "multicast"},
		{"240.0.0.0/8", "multicast"},
		{"169.254.1.0/24", "link-local"},
		{"169.254.169.254", "link-local"},
		{"10.20.30.400", "valid IPv4"},
		{"10.20.30", "valid IPv4"},
		{"010.20.30.40", "valid IPv4"}, // leading zero is ambiguous (octal)
		{"10.20.30.40/33", "CIDR"},
		{"10.20.30.40/", "CIDR"},
		{"10.20.30.40/abc", "CIDR"},
		{"10.20.30.40:80", "valid IPv4"},
		{"", ""},
		{"not a host", ""},
		{"*.com", ""},
	}
	for _, tc := range cases {
		_, err := ParseEntry(tc.in)
		if err == nil {
			t.Errorf("ParseEntry(%q) accepted, want an error", tc.in)
			continue
		}
		if IsValidEntry(tc.in) {
			t.Errorf("IsValidEntry(%q) = true", tc.in)
		}
		if !strings.Contains(err.Error(), tc.wantMsg) {
			t.Errorf("ParseEntry(%q) error = %q, want it to mention %q", tc.in, err, tc.wantMsg)
		}
	}
}

func TestClassifyEntry(t *testing.T) {
	for in, want := range map[string]EntryKind{
		"example.com":     EntryDomain,
		"*.example.com":   EntryDomain,
		"10.20.30.40":     EntryIP,
		"10.20.30.40/32":  EntryIP,
		"10.20.0.0/16":    EntryCIDR,
		"10.0.0.0/7":      EntryCIDR, // invalid, but a CIDR by shape
		"999.1.1.1":       EntryIP,   // invalid, but an IP by shape
		"::1":             EntryIP,
		"not a host name": EntryDomain,
	} {
		if got := ClassifyEntry(in); got != want {
			t.Errorf("ClassifyEntry(%q) = %v, want %v", in, got, want)
		}
	}
	if !IsLiteralEntry("10.0.0.1") || !IsLiteralEntry("10.0.0.0/8") || IsLiteralEntry("example.com") {
		t.Error("IsLiteralEntry must be true for IP and CIDR entries only")
	}
}

func TestNormalizeDomainsCanonicalizesAndDeduplicatesEntries(t *testing.T) {
	got := NormalizeDomains([]DomainRule{
		{Pattern: " Example.COM "},
		{Pattern: "10.20.5.1/16"},
		{Pattern: "10.20.0.0/16"}, // the same network as above
		{Pattern: "10.20.30.40/32"},
		{Pattern: "10.20.30.40"}, // the same host as above
		{Pattern: "10.0.0.0/7"},  // invalid: kept so Validate reports it
	})
	want := []string{"example.com", "10.20.0.0/16", "10.20.30.40", "10.0.0.0/7"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i, r := range got {
		if r.Pattern != want[i] {
			t.Errorf("entry %d = %q, want %q", i, r.Pattern, want[i])
		}
	}
}

func TestValidateAcceptsEntriesAndNamesTheBadOne(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Domains = []DomainRule{{Pattern: "example.com"}, {Pattern: "10.20.30.40"}, {Pattern: "10.20.5.1/16"}}
	cfg.VPNs = []VPNRoute{{Client: testenv.Exe("/Applications/VPN.app/vpn"), Domains: []DomainRule{{Pattern: "172.16.0.0/12"}}}}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}

	for _, bad := range []string{"2001:db8::1", "10.0.0.0/7", "127.0.0.1", "224.0.0.0/4", "169.254.1.0/24", "0.0.0.0/8"} {
		cfg := DefaultConfig()
		cfg.Domains = []DomainRule{{Pattern: "example.com"}, {Pattern: bad}}
		err := cfg.Validate()
		if err == nil {
			t.Errorf("Validate accepted %q", bad)
			continue
		}
		if !strings.Contains(err.Error(), "domain[1]") || !strings.Contains(err.Error(), bad) {
			t.Errorf("Validate(%q) error = %q, want it to name the entry and its index", bad, err)
		}
	}

	cfg = DefaultConfig()
	cfg.VPNs = []VPNRoute{{Client: testenv.Exe("/Applications/VPN.app/vpn"), Domains: []DomainRule{{Pattern: "10.0.0.0/7"}}}}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "vpns[0].domain[0]") {
		t.Errorf("a bad entry in a VPN list must be reported with its list: %v", err)
	}
}

func TestEntriesAreNeverWildcards(t *testing.T) {
	for _, entry := range []string{"10.20.30.40", "10.20.0.0/16"} {
		if IsWildcardPattern(entry) || WildcardSuffix(entry) != "" {
			t.Errorf("%q must not be seen as a wildcard", entry)
		}
		if IsValidDomainPattern(entry) {
			t.Errorf("IsValidDomainPattern(%q) must stay false: it validates domains only", entry)
		}
	}
}
