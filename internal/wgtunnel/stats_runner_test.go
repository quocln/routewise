package wgtunnel

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestParseStats(t *testing.T) {
	text := "private_key=" + strings.Repeat("ab", 32) + "\n" +
		"listen_port=51820\n" +
		"public_key=" + Key{2}.hex() + "\n" +
		"preshared_key=" + strings.Repeat("00", 32) + "\n" +
		"protocol_version=1\n" +
		"endpoint=203.0.113.9:51820\n" +
		"last_handshake_time_sec=1761600000\n" +
		"last_handshake_time_nsec=500\n" +
		"tx_bytes=1234\n" +
		"rx_bytes=5678\n" +
		"persistent_keepalive_interval=25\n" +
		"allowed_ip=10.8.0.0/24\n" +
		"public_key=" + Key{3}.hex() + "\n" +
		"last_handshake_time_sec=0\n" +
		"last_handshake_time_nsec=0\n" +
		"tx_bytes=0\n" +
		"rx_bytes=0\n" +
		"allowed_ip=10.9.0.5/32\n"
	st, err := ParseStats(text)
	if err != nil {
		t.Fatal(err)
	}
	if len(st.Peers) != 2 {
		t.Fatalf("peers = %d", len(st.Peers))
	}
	p := st.Peers[0]
	if p.PublicKey != (Key{2}) || p.Endpoint != netip.MustParseAddrPort("203.0.113.9:51820") ||
		p.RxBytes != 5678 || p.TxBytes != 1234 ||
		!p.LastHandshake.Equal(time.Unix(1761600000, 500)) {
		t.Fatalf("peer0 = %+v", p)
	}
	q := st.Peers[1]
	if q.Endpoint.IsValid() || !q.LastHandshake.IsZero() {
		t.Fatalf("peer1 = %+v", q)
	}
}

func TestParseStatsErrors(t *testing.T) {
	for _, text := range []string{
		"public_key=zz\n",
		"public_key=" + Key{2}.hex() + "\nrx_bytes=abc\n",
		"garbage\n",
	} {
		if _, err := ParseStats(text); err == nil {
			t.Errorf("expected error for %q", text)
		}
	}
}

type call struct {
	name string
	args []string
}

// fakeLinks records the address and link-up requests Start makes, in the
// OS-neutral form of tunnelnet.Links.
type fakeLinks struct {
	calls  []call
	failOn int // 1-based call number to fail, 0 = never
}

func (f *fakeLinks) record(name string, args ...string) error {
	f.calls = append(f.calls, call{name, args})
	if f.failOn == len(f.calls) {
		return errors.New("boom")
	}
	return nil
}

func (f *fakeLinks) AddAlias(_ context.Context, iface, local, peer string) error {
	return f.record("addalias", iface, local, peer)
}

func (f *fakeLinks) Up(_ context.Context, iface string) error { return f.record("up", iface) }

func TestAssignAddresses(t *testing.T) {
	f := &fakeLinks{}
	addrs := []netip.Prefix{
		netip.MustParsePrefix("10.8.0.2/24"),
		netip.MustParsePrefix("fd00::2/64"), // IPv6 skipped
		netip.MustParsePrefix("10.9.0.2/32"),
	}
	if err := assignAddresses(context.Background(), f, "utun7", addrs); err != nil {
		t.Fatal(err)
	}
	want := []call{
		{"addalias", []string{"utun7", "10.8.0.2/32", "10.8.0.2"}},
		{"addalias", []string{"utun7", "10.9.0.2/32", "10.9.0.2"}},
		{"up", []string{"utun7"}},
	}
	if !reflect.DeepEqual(f.calls, want) {
		t.Fatalf("calls = %v\nwant %v", f.calls, want)
	}
}

func TestAssignAddressesFailure(t *testing.T) {
	f := &fakeLinks{failOn: 1}
	err := assignAddresses(context.Background(), f, "utun7", []netip.Prefix{netip.MustParsePrefix("10.8.0.2/24")})
	if err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("err = %v", err)
	}
	if len(f.calls) != 1 {
		t.Fatalf("kept going after failure: %v", f.calls)
	}
}

func TestExecRunnerRejectsRelativePath(t *testing.T) {
	if _, err := (ExecRunner{}).Run(context.Background(), "ifconfig", "lo0"); err == nil {
		t.Fatal("expected refusal of non-absolute command")
	}
}
