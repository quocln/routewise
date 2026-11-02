package daemon

import (
	"fmt"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/quocln/routewise/internal/config"
	"github.com/quocln/routewise/internal/configdb"
	"github.com/quocln/routewise/internal/dnswatch"
	"github.com/quocln/routewise/internal/route"
	"github.com/quocln/routewise/internal/vpnclient"
)

// benchDaemon builds a daemon holding 500 patterns across the Any VPN list and
// two VPN lists, with one registered session per VPN, without starting it.
func benchDaemon(b *testing.B) *Daemon {
	b.Helper()
	cfg := newTestDaemonConfig(b.TempDir())
	cfg.Domains = nil
	var anyRules, wgRules, awsRules []config.DomainRule
	for i := range 100 {
		anyRules = append(anyRules,
			config.DomainRule{Pattern: fmt.Sprintf("*.any%d.example.com", i)},
			config.DomainRule{Pattern: fmt.Sprintf("host%d.any.example.com", i)})
		wgRules = append(wgRules,
			config.DomainRule{Pattern: fmt.Sprintf("*.wg%d.example.net", i)},
			config.DomainRule{Pattern: fmt.Sprintf("10.%d.0.0/16", 20+i%200)})
		awsRules = append(awsRules, config.DomainRule{Pattern: fmt.Sprintf("*.aws%d.example.org", i)})
	}
	cfg.Domains = anyRules
	cfg.VPNs = []config.VPNRoute{
		{Client: wireGuardPath, Domains: wgRules},
		{Client: awsClientPath, Domains: awsRules},
	}
	d, err := New(cfg, nil)
	if err != nil {
		b.Fatal(err)
	}
	for i, c := range []struct{ iface, path string }{{wgIface, wireGuardPath}, {awsIface, awsClientPath}} {
		s := &tunnelSession{
			iface:   c.iface,
			gateway: netip.MustParseAddr("10.0.0.1"),
			client:  vpnclient.FromPath(c.path),
			manager: route.NewManager(),
			learned: map[netip.Addr]learnedRoute{},
		}
		_ = i
		d.sessions.add(s)
	}
	return d
}

func BenchmarkOwnerForNoMatch(b *testing.B) {
	d := benchDaemon(b)
	b.ReportAllocs()
	for b.Loop() {
		d.ownerFor("nothing.example.invalid")
	}
}

func BenchmarkOwnerForMidListWildcard(b *testing.B) {
	d := benchDaemon(b)
	b.ReportAllocs()
	for b.Loop() {
		d.ownerFor("api.aws50.example.org")
	}
}

func BenchmarkOnFlow(b *testing.B) {
	d := benchDaemon(b)
	d.historyOn.Store(true)
	d.OpenHistory(openSharedDB(b, filepath.Join(b.TempDir(), configdb.FileName)))
	defer d.closeHistory()
	flow := dnswatch.Flow{
		Time: time.Now(), Interface: "en0", Proto: "tcp", DstPort: 443,
		Dst: netip.MustParseAddr("203.0.113.9"),
	}
	b.ReportAllocs()
	for b.Loop() {
		d.onFlow(flow)
	}
}

func BenchmarkMatchingEntry(b *testing.B) {
	d := benchDaemon(b)
	b.ReportAllocs()
	for b.Loop() {
		d.matchEntry("api.aws50.example.org", netip.MustParseAddr("203.0.113.9"))
	}
}

func (d *Daemon) matchEntry(name string, ip netip.Addr) (listMatch, bool) {
	return d.store.Policy().matchingEntry(name, ip)
}
