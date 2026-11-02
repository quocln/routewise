package config

import (
	"fmt"
	"net/netip"
	"strings"
)

// EntryKind says what a domain-list entry is.
type EntryKind int

const (
	// EntryDomain is a domain pattern: an exact name or a wildcard.
	EntryDomain EntryKind = iota
	// EntryIP is a single IPv4 address, routed as a /32.
	EntryIP
	// EntryCIDR is an IPv4 network, routed as a network route.
	EntryCIDR
)

// MinEntryPrefixBits is the shortest CIDR a list may hold. Anything broader
// would capture a large part of the address space.
const MinEntryPrefixBits = 8

// reservedBlock is an IPv4 range that no list entry may be or overlap.
type reservedBlock struct {
	prefix netip.Prefix
	name   string
}

// reservedBlocks are the ranges a list entry may never touch: routing them
// through a tunnel would break local services (loopback, link-local) or is
// meaningless (this-network, multicast, reserved, broadcast).
var reservedBlocks = []reservedBlock{
	{netip.MustParsePrefix("0.0.0.0/8"), "this network"},
	{netip.MustParsePrefix("127.0.0.0/8"), "loopback"},
	{netip.MustParsePrefix("169.254.0.0/16"), "link-local"},
	{netip.MustParsePrefix("224.0.0.0/3"), "multicast and reserved"},
}

// Entry is a parsed domain-list entry.
type Entry struct {
	Kind EntryKind
	// Value is the canonical text: a CIDR is its network address and a /32
	// is the plain IP. A domain is returned as given.
	Value string
	// Addr is the address of an EntryIP.
	Addr netip.Addr
	// Prefix is the masked network of an EntryCIDR.
	Prefix netip.Prefix
}

// looksNumeric reports whether s is made only of digits and dots, which no
// domain pattern is (a pattern ends in a letter-only label), so it must be a
// malformed IPv4 address.
func looksNumeric(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if (r < '0' || r > '9') && r != '.' {
			return false
		}
	}
	return true
}

// ParseEntry classifies and validates a list entry. For an IP or CIDR the
// returned Entry carries the canonical form; the error says why an invalid one
// was rejected. For a domain the error is non-specific, as IsValidDomainPattern
// is the authority on domains.
func ParseEntry(s string) (Entry, error) {
	switch {
	case strings.Contains(s, "/"):
		p, err := netip.ParsePrefix(s)
		if err != nil {
			if looksIPv6(s) {
				return Entry{}, errIPv6
			}
			return Entry{}, fmt.Errorf("not a valid IPv4 CIDR such as 10.20.0.0/16")
		}
		if !p.Addr().Is4() {
			return Entry{}, errIPv6
		}
		if p.Bits() < MinEntryPrefixBits {
			return Entry{}, fmt.Errorf("/%d is too broad: the shortest CIDR allowed is /%d", p.Bits(), MinEntryPrefixBits)
		}
		if err := checkReserved(p); err != nil {
			return Entry{}, err
		}
		p = p.Masked()
		if p.Bits() == 32 {
			return Entry{Kind: EntryIP, Value: p.Addr().String(), Addr: p.Addr()}, nil
		}
		return Entry{Kind: EntryCIDR, Value: p.String(), Prefix: p}, nil

	case strings.Contains(s, ":"):
		if looksIPv6(s) {
			return Entry{}, errIPv6
		}
		return Entry{}, fmt.Errorf("not a valid IPv4 address")

	default:
		if a, err := netip.ParseAddr(s); err == nil {
			if err := checkReserved(netip.PrefixFrom(a, 32)); err != nil {
				return Entry{}, err
			}
			return Entry{Kind: EntryIP, Value: a.String(), Addr: a}, nil
		}
		if looksNumeric(s) {
			return Entry{}, fmt.Errorf("not a valid IPv4 address")
		}
		if IsValidDomainPattern(s) {
			return Entry{Kind: EntryDomain, Value: s}, nil
		}
		return Entry{}, fmt.Errorf("not a valid domain pattern, IPv4 address, or IPv4 CIDR")
	}
}

// looksIPv6 reports whether s is written as an IPv6 address: two or more
// colons. A single colon is an IPv4 address with a port, which is just invalid.
func looksIPv6(s string) bool { return strings.Count(s, ":") >= 2 }

var errIPv6 = fmt.Errorf("IPv6 is not supported; use an IPv4 address or CIDR")

// checkReserved rejects a prefix that is or overlaps a reserved block.
func checkReserved(p netip.Prefix) error {
	for _, b := range reservedBlocks {
		if b.prefix.Overlaps(p) {
			return fmt.Errorf("%s is or overlaps %s (%s), which cannot be routed", p, b.prefix, b.name)
		}
	}
	return nil
}

// ClassifyEntry reports whether s is a domain pattern, an IP, or a CIDR. An
// entry that is not valid is reported as a domain, since the domain rules
// are the ones it fails.
func ClassifyEntry(s string) EntryKind {
	if e, err := ParseEntry(s); err == nil {
		return e.Kind
	}
	if strings.Contains(s, "/") {
		return EntryCIDR
	}
	if strings.Contains(s, ":") || looksNumeric(s) {
		return EntryIP
	}
	return EntryDomain
}

// IsLiteralEntry reports whether s is an IP or CIDR entry rather than a domain
// pattern: such entries are routed as given and never resolved or looked up.
func IsLiteralEntry(s string) bool {
	return ClassifyEntry(s) != EntryDomain
}

// IsValidEntry reports whether s is a valid list entry: a domain pattern (see
// IsValidDomainPattern), an IPv4 address, or an IPv4 CIDR no shorter than /8
// that avoids the reserved ranges. It is the single validator for the config
// file, the socket API, and the CLI.
func IsValidEntry(s string) bool {
	_, err := ParseEntry(s)
	return err == nil
}

// NormalizeEntry trims and lowercases s and, for a valid IP or CIDR, returns
// its canonical form: a CIDR becomes its network address
// (10.20.5.1/16 -> 10.20.0.0/16) and x/32 becomes the plain IP. An invalid
// entry is returned trimmed and lowercased, so validation still reports it.
func NormalizeEntry(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if e, err := ParseEntry(s); err == nil {
		return e.Value
	}
	return s
}
