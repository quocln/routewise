package route

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
)

// ipv6RejectGateway is the next hop a reject route names. The kernel never
// forwards through it: the reject flag fails the connection first.
const ipv6RejectGateway = "::1"

// AddIPv6Reject adds a host route that makes connections to addr fail at once
// (`route -n add -inet6 -host <addr> ::1 -reject`). A route that already exists
// is accepted, so a leftover of an earlier process is adopted.
func AddIPv6Reject(ctx context.Context, runner CommandRunner, addr netip.Addr) error {
	if err := ValidateBlockableIPv6(addr); err != nil {
		return fmt.Errorf("AddIPv6Reject: %w", err)
	}
	_, err := runner.Run(ctx, toolRoute, "-n", "add", "-inet6", "-host", addr.String(), ipv6RejectGateway, "-reject")
	if err != nil && !strings.Contains(err.Error(), "File exists") {
		return err
	}
	return nil
}

// DeleteIPv6Reject removes the reject host route for addr. A route that is
// already gone is not an error.
func DeleteIPv6Reject(ctx context.Context, runner CommandRunner, addr netip.Addr) error {
	if err := ValidateBlockableIPv6(addr); err != nil {
		return fmt.Errorf("DeleteIPv6Reject: %w", err)
	}
	_, err := runner.Run(ctx, toolRoute, "-n", "delete", "-inet6", "-host", addr.String())
	if err != nil && !strings.Contains(err.Error(), "not in table") {
		return err
	}
	return nil
}

// addIPv6RejectAll is AddIPv6Reject for every global IPv6 address.
func addIPv6RejectAll(ctx context.Context, runner CommandRunner) error {
	_, err := runner.Run(ctx, toolRoute, "-n", "add", "-inet6", "-net", globalUnicastV6.String(), ipv6RejectGateway, "-reject")
	if err != nil && !strings.Contains(err.Error(), "File exists") {
		return err
	}
	return nil
}

// deleteIPv6RejectAll removes the route addIPv6RejectAll added.
func deleteIPv6RejectAll(ctx context.Context, runner CommandRunner) error {
	_, err := runner.Run(ctx, toolRoute, "-n", "delete", "-inet6", "-net", globalUnicastV6.String())
	if err != nil && !strings.Contains(err.Error(), "not in table") {
		return err
	}
	return nil
}
