//go:build !darwin && !linux && !windows

package route

import (
	"context"
	"net/netip"

	"github.com/quocln/routewise/internal/platform"
)

// systemTable reports every operation as unsupported: this OS has no route
// table implementation yet.
func systemTable() Table { return unsupportedTable{} }

// unsupportedTable is the Table of a platform without an implementation.
type unsupportedTable struct{}

var errTableUnsupported = platform.Unsupported("route table access")

func (unsupportedTable) Snapshot(context.Context) ([]RouteEntry, error) {
	return nil, errTableUnsupported
}
func (unsupportedTable) Default(context.Context) (netip.Addr, string, error) {
	return netip.Addr{}, "", errTableUnsupported
}
func (unsupportedTable) DefaultGateway(context.Context) (netip.Addr, error) {
	return netip.Addr{}, errTableUnsupported
}
func (unsupportedTable) LocalGateway(context.Context, string) (netip.Addr, string, error) {
	return netip.Addr{}, "", errTableUnsupported
}
func (unsupportedTable) Lookup(context.Context, netip.Addr) (string, netip.Addr, error) {
	return "", netip.Addr{}, errTableUnsupported
}
func (unsupportedTable) AddHost(context.Context, netip.Addr, netip.Addr, string) error {
	return errTableUnsupported
}
func (unsupportedTable) AddPrefix(context.Context, netip.Prefix, netip.Addr, string) error {
	return errTableUnsupported
}
func (unsupportedTable) AddNet(context.Context, string, string, string) error {
	return errTableUnsupported
}
func (unsupportedTable) DeleteHost(context.Context, netip.Addr) error { return errTableUnsupported }
func (unsupportedTable) DeleteNet(context.Context, string, string, string) error {
	return errTableUnsupported
}
func (unsupportedTable) DropClonedLinkLayer(context.Context, netip.Addr) {}
func (unsupportedTable) ChangeDefault(context.Context, netip.Addr) error {
	return errTableUnsupported
}
func (unsupportedTable) ChangeDefaultStrict(context.Context, netip.Addr) error {
	return errTableUnsupported
}
func (unsupportedTable) ReplaceDefault(context.Context, netip.Addr) error {
	return errTableUnsupported
}
func (unsupportedTable) ChangeDefaultToInterface(context.Context, string) error {
	return errTableUnsupported
}
func (unsupportedTable) AddIPv6Reject(context.Context, netip.Addr) error {
	return errTableUnsupported
}
func (unsupportedTable) DeleteIPv6Reject(context.Context, netip.Addr) error {
	return errTableUnsupported
}
func (unsupportedTable) AddIPv6RejectAll(context.Context) error {
	return errTableUnsupported
}
func (unsupportedTable) DeleteIPv6RejectAll(context.Context) error {
	return errTableUnsupported
}
func (unsupportedTable) IsUnreachable(error) bool { return false }
