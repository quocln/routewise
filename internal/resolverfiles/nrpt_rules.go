package resolverfiles

import (
	"crypto/sha256"
	"encoding/hex"
	"net/netip"
)

// Windows reads split-DNS policy from the Name Resolution Policy Table (NRPT):
// one registry subkey per rule under Dnscache's DnsPolicyConfig. The rendering
// here is plain data so it can be checked on any OS; nrpt_backend_windows.go
// writes it.
const (
	// nrptKeyPrefix starts the name of every rule RouteWise owns. Only keys
	// carrying it are ever rewritten or removed.
	nrptKeyPrefix = "RouteWise-"
	// nrptVersion is the rule format Windows 8 and later write.
	nrptVersion = 2
	// nrptGenericDNS is the ConfigOptions bit that says GenericDNSServers
	// holds the servers to ask.
	nrptGenericDNS = 0x8
	// nrptComment marks the rule as RouteWise's for anyone reading the table.
	nrptComment = "Managed by RouteWise. Removed automatically when the VPN disconnects."
)

// regKind is the registry value type of a regValue.
type regKind int

const (
	regDWord regKind = iota
	regString
	regMultiString
)

// regValue is one value of a registry key.
type regValue struct {
	name  string
	kind  regKind
	dword uint32   // regDWord
	str   string   // regString
	multi []string // regMultiString
}

// nrptRule is one rule: every name under domain goes to server.
type nrptRule struct {
	domain string
	server netip.Addr
}

// key is the rule's registry key name. It is derived from the domain, so the
// same domain always lands on the same key, and it avoids characters and
// lengths the registry would refuse.
func (r nrptRule) key() string { return nrptRuleKey(r.domain) }

func nrptRuleKey(domain string) string {
	sum := sha256.Sum256([]byte(domain))
	return nrptKeyPrefix + hex.EncodeToString(sum[:8])
}

// names are the namespaces the rule covers. A leading dot is a suffix match,
// which takes every name below the domain; the bare name is an exact match for
// the domain itself, so the apex is covered whichever way the DNS client reads
// the suffix form.
func (r nrptRule) names() []string { return []string{"." + r.domain, r.domain} }

// values are the registry values of the rule's key.
func (r nrptRule) values() []regValue {
	return []regValue{
		{name: "Version", kind: regDWord, dword: nrptVersion},
		{name: "Name", kind: regMultiString, multi: r.names()},
		{name: "GenericDNSServers", kind: regString, str: r.server.String()},
		{name: "ConfigOptions", kind: regDWord, dword: nrptGenericDNS},
		{name: "IPSECCARestriction", kind: regString, str: ""},
		{name: "Comment", kind: regString, str: nrptComment},
		{name: "DisplayName", kind: regString, str: "RouteWise " + r.domain},
	}
}
