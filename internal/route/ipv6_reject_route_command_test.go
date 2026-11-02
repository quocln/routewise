package route

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
)

type recordingRunner struct {
	calls []string
	err   error
}

func (r *recordingRunner) Run(_ context.Context, tool string, args ...string) (string, error) {
	r.calls = append(r.calls, tool+" "+strings.Join(args, " "))
	return "", r.err
}

func TestIPv6RejectRouteCommands(t *testing.T) {
	r := &recordingRunner{}
	addr := netip.MustParseAddr("2001:db8::1")
	if err := AddIPv6Reject(context.Background(), r, addr); err != nil {
		t.Fatal(err)
	}
	if err := DeleteIPv6Reject(context.Background(), r, addr); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"route -n add -inet6 -host 2001:db8::1 ::1 -reject",
		"route -n delete -inet6 -host 2001:db8::1",
	}
	if strings.Join(r.calls, "|") != strings.Join(want, "|") {
		t.Fatalf("calls = %q, want %q", r.calls, want)
	}
}

func TestIPv6RejectRouteToleratesExistingAndMissing(t *testing.T) {
	addr := netip.MustParseAddr("2001:db8::1")
	if err := AddIPv6Reject(context.Background(), &recordingRunner{err: errors.New("route: writing to routing socket: File exists")}, addr); err != nil {
		t.Errorf("an existing route must be adopted: %v", err)
	}
	if err := DeleteIPv6Reject(context.Background(), &recordingRunner{err: errors.New("route: writing to routing socket: not in table")}, addr); err != nil {
		t.Errorf("a missing route is already deleted: %v", err)
	}
	if err := AddIPv6Reject(context.Background(), &recordingRunner{err: errors.New("operation not permitted")}, addr); err == nil {
		t.Error("another failure must be reported")
	}
}

func TestIPv6RejectRouteRefusesInvalidAddressWithoutRunning(t *testing.T) {
	r := &recordingRunner{}
	for _, bad := range []string{"::1", "fe80::1", "10.0.0.1"} {
		a := netip.MustParseAddr(bad)
		if AddIPv6Reject(context.Background(), r, a) == nil || DeleteIPv6Reject(context.Background(), r, a) == nil {
			t.Errorf("%s must be refused", bad)
		}
	}
	if len(r.calls) != 0 {
		t.Fatalf("ran %q for refused addresses", r.calls)
	}
}

func TestIPv6RejectAllRouteCommands(t *testing.T) {
	r := &recordingRunner{}
	if err := addIPv6RejectAll(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	if err := deleteIPv6RejectAll(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"route -n add -inet6 -net 2000::/3 ::1 -reject",
		"route -n delete -inet6 -net 2000::/3",
	}
	if strings.Join(r.calls, "|") != strings.Join(want, "|") {
		t.Fatalf("calls = %q, want %q", r.calls, want)
	}

	// A leftover is adopted, and a route already gone is not an error.
	if err := addIPv6RejectAll(context.Background(), &recordingRunner{err: errors.New("route: File exists")}); err != nil {
		t.Errorf("add over an existing route: %v", err)
	}
	if err := deleteIPv6RejectAll(context.Background(), &recordingRunner{err: errors.New("route: not in table")}); err != nil {
		t.Errorf("delete of a missing route: %v", err)
	}
}
