package tunnelnet

import (
	"context"
	"net/netip"
	"testing"
)

func TestExecRunnerRejectsRelativePath(t *testing.T) {
	if _, err := (ExecRunner{}).Run(context.Background(), "ifconfig", "lo0"); err == nil {
		t.Fatal("relative command path must be refused")
	}
}

func TestPreferIPv4(t *testing.T) {
	a := netip.MustParseAddr
	tests := []struct {
		name  string
		in    []netip.Addr
		want  netip.Addr
		found bool
	}{
		{"empty", nil, netip.Addr{}, false},
		{"v6 first, v4 later", []netip.Addr{a("2001:db8::1"), a("192.0.2.1")}, a("192.0.2.1"), true},
		{"only v6", []netip.Addr{a("2001:db8::1"), a("2001:db8::2")}, a("2001:db8::1"), true},
		{"mapped v4 is unmapped", []netip.Addr{a("::ffff:192.0.2.9")}, a("192.0.2.9"), true},
	}
	for _, tt := range tests {
		got, ok := PreferIPv4(tt.in)
		if ok != tt.found || got != tt.want {
			t.Errorf("%s: got %v,%v want %v,%v", tt.name, got, ok, tt.want, tt.found)
		}
	}
}
