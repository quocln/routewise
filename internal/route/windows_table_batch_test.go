package route

import (
	"context"
	"fmt"
	"net/netip"
	"testing"

	"github.com/quocln/routewise/internal/winnet"
)

// countingOps counts reads of the route and adapter tables.
type countingOps struct {
	*fakeWinOps
	routeReads, adapterReads int
}

func (c *countingOps) routes(family int) ([]winnet.Route, error) {
	c.routeReads++
	return c.fakeWinOps.routes(family)
}

func (c *countingOps) adapters() ([]winnet.Adapter, error) {
	c.adapterReads++
	return c.fakeWinOps.adapters()
}

func TestABatchReadsTheTablesOnceForManyChanges(t *testing.T) {
	const hosts = 50
	for _, batched := range []bool{false, true} {
		ops := &countingOps{fakeWinOps: withOpenVPN(lanTable())}
		tab := newWindowsTable(ops)
		ctx := context.Background()
		if batched {
			tab.BeginBatch()
		}
		for i := range hosts {
			dest := netip.MustParseAddr(fmt.Sprintf("93.184.216.%d", i+1))
			if err := tab.AddHost(ctx, dest, netip.MustParseAddr("10.8.0.1"), tap.Alias); err != nil {
				t.Fatal(err)
			}
		}
		// An address added in the batch is seen by the next add: adopted, not duplicated.
		if err := tab.AddHost(ctx, netip.MustParseAddr("93.184.216.1"), netip.MustParseAddr("10.8.0.1"), tap.Alias); err != nil {
			t.Fatal(err)
		}
		for i := range hosts / 2 {
			if err := tab.DeleteHost(ctx, netip.MustParseAddr(fmt.Sprintf("93.184.216.%d", i+1))); err != nil {
				t.Fatal(err)
			}
		}
		if batched {
			tab.EndBatch()
		}

		if got := len(routesTo(ops.fakeWinOps.table, netip.MustParsePrefix("93.184.216.40/32"))); got != 1 {
			t.Fatalf("batched=%v: 93.184.216.40 has %d routes, want 1", batched, got)
		}
		if got := len(routesTo(ops.fakeWinOps.table, netip.MustParsePrefix("93.184.216.3/32"))); got != 0 {
			t.Fatalf("batched=%v: a deleted route is still there", batched)
		}
		t.Logf("batched=%v: %d route reads, %d adapter reads for %d adds and %d deletes", batched, ops.routeReads, ops.adapterReads, hosts+1, hosts/2)
		if batched && (ops.routeReads != 1 || ops.adapterReads != 1) {
			t.Fatalf("batch read the tables %d and %d times, want once each", ops.routeReads, ops.adapterReads)
		}
		if !batched && ops.routeReads < hosts {
			t.Fatalf("without a batch every change reads the table; got %d reads", ops.routeReads)
		}
	}
}

func TestAnEndedBatchReadsFreshAgain(t *testing.T) {
	ops := &countingOps{fakeWinOps: withOpenVPN(lanTable())}
	tab := newWindowsTable(ops)
	ctx := context.Background()
	tab.BeginBatch()
	tab.BeginBatch()
	_ = tab.AddHost(ctx, netip.MustParseAddr("93.184.216.1"), netip.MustParseAddr("10.8.0.1"), tap.Alias)
	tab.EndBatch() // still inside the outer batch
	_ = tab.AddHost(ctx, netip.MustParseAddr("93.184.216.2"), netip.MustParseAddr("10.8.0.1"), tap.Alias)
	if ops.routeReads != 1 {
		t.Fatalf("reads = %d inside nested batches, want 1", ops.routeReads)
	}
	tab.EndBatch()
	_ = tab.AddHost(ctx, netip.MustParseAddr("93.184.216.3"), netip.MustParseAddr("10.8.0.1"), tap.Alias)
	if ops.routeReads != 2 {
		t.Fatalf("reads = %d after the batch ended, want a fresh read", ops.routeReads)
	}
}

func BenchmarkWindowsTableAddHosts(b *testing.B) {
	for _, batched := range []bool{false, true} {
		b.Run(fmt.Sprintf("batched=%v", batched), func(b *testing.B) {
			base := lanTable()
			for i := range 3000 { // a table the size of a big session
				base.table = append(base.table, rt(wintun, fmt.Sprintf("10.%d.%d.1/32", i/250, i%250), "", 0, 3))
			}
			ops := &countingOps{fakeWinOps: withOpenVPN(base)}
			tab := newWindowsTable(ops)
			ctx := context.Background()
			b.ReportAllocs()
			i := 0
			for b.Loop() {
				if batched && i%50 == 0 {
					tab.BeginBatch()
				}
				dest := netip.AddrFrom4([4]byte{93, 184, byte(i / 250 % 250), byte(i%250 + 1)})
				_ = tab.AddHost(ctx, dest, netip.MustParseAddr("10.8.0.1"), tap.Alias)
				i++
				if batched && i%50 == 0 {
					tab.EndBatch()
				}
			}
		})
	}
}
