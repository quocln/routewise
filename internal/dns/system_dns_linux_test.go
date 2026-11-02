package dns

import (
	"context"
	"os"
	"testing"

	"github.com/quocln/routewise/internal/resolverfiles"
)

// With RouteWise's split-DNS link in place, the system configuration read back
// from systemd-resolved must not contain it: the forwarder's own upstreams are
// never the forwarder. Needs root (to create the link) and a running resolved.
func TestSystemDNSConfigOmitsRouteWiseLink(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to manage network links")
	}
	if _, err := os.Stat("/run/systemd/resolve/io.systemd.Resolve"); err != nil {
		t.Skip("systemd-resolved is not running")
	}
	c := resolverfiles.NewSystem("127.0.0.1", 53981)
	t.Cleanup(func() { c.RemoveAll() })
	if _, err := c.Apply([]string{"routewise-live.test"}); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	out, err := systemDNSConfig(context.Background())
	if err != nil {
		t.Fatalf("systemDNSConfig: %v", err)
	}
	for _, b := range parseResolverBlocks(out) {
		if b.iface == resolverfiles.LinkName {
			t.Errorf("RouteWise's link is in the system configuration:\n%s", out)
		}
		for _, s := range b.servers {
			if s.IsLoopback() {
				t.Errorf("loopback server %v offered:\n%s", s, out)
			}
		}
	}
	servers, err := SystemNameservers(context.Background())
	if err != nil || len(servers) == 0 {
		t.Errorf("SystemNameservers = %v, %v; want the host's upstream servers", servers, err)
	}
}
