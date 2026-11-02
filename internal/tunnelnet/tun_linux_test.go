//go:build linux

package tunnelnet

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/vishvananda/netlink"
)

func TestPointToPointAddr(t *testing.T) {
	t.Run("peer is the address itself", func(t *testing.T) {
		a, err := pointToPointAddr("10.8.0.2/32", "10.8.0.2")
		if err != nil {
			t.Fatal(err)
		}
		if a.IPNet.String() != "10.8.0.2/32" || a.Peer != nil {
			t.Fatalf("addr = %v peer %v, want a plain /32", a.IPNet, a.Peer)
		}
	})
	t.Run("bare address is a /32", func(t *testing.T) {
		a, err := pointToPointAddr("10.8.0.2", "10.8.0.2")
		if err != nil || a.IPNet.String() != "10.8.0.2/32" {
			t.Fatalf("addr = %v, err = %v", a, err)
		}
	})
	t.Run("distinct peer", func(t *testing.T) {
		a, err := pointToPointAddr("10.8.0.2", "10.8.0.1")
		if err != nil {
			t.Fatal(err)
		}
		if a.IPNet.String() != "10.8.0.2/32" || a.Peer == nil || a.Peer.String() != "10.8.0.1/32" {
			t.Fatalf("addr = %v peer %v", a.IPNet, a.Peer)
		}
	})
	for _, bad := range [][2]string{
		{"nonsense", "10.8.0.2"},
		{"10.8.0.2", "nonsense"},
		{"fd00::2/128", "fd00::2"},
		{"10.8.0.2", "fd00::1"},
	} {
		if _, err := pointToPointAddr(bad[0], bad[1]); err == nil {
			t.Errorf("pointToPointAddr(%q, %q) accepted bad input", bad[0], bad[1])
		}
	}
}

func TestAddAliasAndUpFailForMissingInterface(t *testing.T) {
	if err := AddAlias(context.Background(), nil, "rw-no-such-iface", "10.8.0.2", "10.8.0.2"); err == nil {
		t.Error("AddAlias on a missing interface must fail")
	}
	if err := Up(context.Background(), nil, "rw-no-such-iface"); err == nil {
		t.Error("Up on a missing interface must fail")
	}
}

// TestCreateTUNAddressUpAsRoot creates a real TUN device, so it needs root; it
// is skipped otherwise. It proves the device is named rwtunN, takes a plain
// /32 without adding a route, and goes up.
func TestCreateTUNAddressUpAsRoot(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	dev, err := CreateTUN(1380)
	if err != nil {
		t.Skipf("cannot create a TUN device here: %v", err)
	}
	defer dev.Close()
	name, err := dev.Name()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(name, "rwtun") {
		t.Fatalf("Name = %q, want rwtunN", name)
	}

	ctx := context.Background()
	if err := AddAlias(ctx, nil, name, "10.233.249.2/32", "10.233.249.2"); err != nil {
		t.Fatal(err)
	}
	if err := Up(ctx, nil, name); err != nil {
		t.Fatal(err)
	}

	link, err := netlink.LinkByName(name)
	if err != nil {
		t.Fatal(err)
	}
	if link.Attrs().MTU != 1380 {
		t.Errorf("MTU = %d, want 1380", link.Attrs().MTU)
	}
	addrs, err := netlink.AddrList(link, netlink.FAMILY_V4)
	if err != nil || len(addrs) != 1 || addrs[0].IPNet.String() != "10.233.249.2/32" {
		t.Fatalf("addrs = %v, err = %v", addrs, err)
	}
	routes, err := netlink.RouteList(link, netlink.FAMILY_V4)
	if err != nil {
		t.Fatal(err)
	}
	if len(routes) != 0 {
		t.Fatalf("routes on %s = %v, want none", name, routes)
	}
}
