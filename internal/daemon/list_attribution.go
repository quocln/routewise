package daemon

// listMatch names the domain-list entry a route or a connection was for.
type listMatch struct {
	// list is the client id of the list holding the entry; "" is Any VPN.
	list string
	// rule is the entry itself: a domain, a wildcard, an IP or a CIDR.
	rule string
}
