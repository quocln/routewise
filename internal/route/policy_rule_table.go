package route

import "context"

// policyRuleTable is what a Table adds when the operating system can route by
// policy rule (Linux). A VPN such as wg-quick sends all unmarked traffic to a
// routing table of its own by a rule ahead of the main table, so the manager's
// edits to the main default never reach unlisted traffic; a rule of its own,
// ahead of the VPN's, makes the main table decide again.
type policyRuleTable interface {
	// MainLookupPriority returns the priority a main-table lookup must have to
	// run just ahead of the rule sending all traffic into iface's own table.
	// found is false when iface is not policy-routed.
	MainLookupPriority(ctx context.Context, iface string) (priority int, found bool, err error)
	// AddMainLookupRule adds a rule of that priority, marked as RouteWise's.
	AddMainLookupRule(ctx context.Context, priority int) error
	// DeleteMainLookupRule removes it; one that is already gone is not an error.
	DeleteMainLookupRule(ctx context.Context, priority int) error
}
