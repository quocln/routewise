package route

import "testing"

const netstatFixture = `Routing tables

Internet:
Destination        Gateway            Flags           Netif Expire
default             192.168.1.1        UGSc              en0
127                 127.0.0.1          UCS               lo0
127.0.0.1           127.0.0.1          UH                lo0
169.254             link#11            UCS               en0       !
192.168.1           link#11            UCS               en0       !
3.112.153.142       utun12             UHS               utun12
0.0.0.0/1           10.8.0.1           UGSc              utun5
128.0.0.0/1         10.8.0.1           UGSc              utun5

Internet6:
Destination                       Gateway                       Flags           Netif Expire
::1                               ::1                           UHL               lo0
fe80::%lo0/64                     fe80::1%lo0                   UcI               lo0
`

func TestParseRouteTable(t *testing.T) {
	entries := parseRouteTable(netstatFixture)

	want := map[string]RouteEntry{
		"default":       {Destination: "default", Gateway: "192.168.1.1", Flags: "UGSc", Interface: "en0"},
		"3.112.153.142": {Destination: "3.112.153.142", Gateway: "utun12", Flags: "UHS", Interface: "utun12"},
		"0.0.0.0/1":     {Destination: "0.0.0.0/1", Gateway: "10.8.0.1", Flags: "UGSc", Interface: "utun5"},
		"128.0.0.0/1":   {Destination: "128.0.0.0/1", Gateway: "10.8.0.1", Flags: "UGSc", Interface: "utun5"},
	}

	for dest, expected := range want {
		got, ok := findRoute(entries, dest)
		if !ok {
			t.Errorf("expected entry for %s, not found in %+v", dest, entries)
			continue
		}
		if got != expected {
			t.Errorf("entry for %s = %+v, want %+v", dest, got, expected)
		}
	}

	for _, e := range entries {
		switch e.Destination {
		case "Destination", "Routing", "Internet:", "Internet6:":
			t.Errorf("header line leaked into parsed entries: %+v", e)
		}
	}

	split := findSplitTunnelRoutes(entries)
	if len(split) != 2 {
		t.Errorf("expected 2 split tunnel routes, got %d: %+v", len(split), split)
	}
}

func TestCanonicalSplitTunnelDest(t *testing.T) {
	tests := []struct {
		raw    string
		want   string
		wantOK bool
	}{
		{"0/1", "0.0.0.0/1", true},
		{"0.0.0.0/1", "0.0.0.0/1", true},
		{"128/1", "128.0.0.0/1", true},
		{"128.0/1", "128.0.0.0/1", true},
		{"128.0.0.0/1", "128.0.0.0/1", true},
		{"default", "", false},
		{"10.0.0.0/8", "", false},
	}

	for _, tt := range tests {
		got, ok := canonicalSplitTunnelDest(tt.raw)
		if ok != tt.wantOK || got != tt.want {
			t.Errorf("canonicalSplitTunnelDest(%q) = (%q, %v), want (%q, %v)", tt.raw, got, ok, tt.want, tt.wantOK)
		}
	}
}

func TestSameGateway(t *testing.T) {
	tests := []struct {
		a, b string
		want bool
	}{
		{"192.168.1.1", "192.168.1.1", true},
		{"utun5", "utun5", true},
		{"192.168.1.1", "192.168.1.2", false},
		{"utun5", "utun6", false},
		// A point-to-point route prints the interface name where an IP would
		// normally appear; comparing that against an unrelated IP must not
		// panic and must report no match.
		{"utun5", "10.8.0.1", false},
	}

	for _, tt := range tests {
		if got := sameGateway(tt.a, tt.b); got != tt.want {
			t.Errorf("sameGateway(%q, %q) = %v, want %v", tt.a, tt.b, got, tt.want)
		}
	}
}

func TestValidateInterfaceNameRejectsInvalid(t *testing.T) {
	tests := append([]string{"", "utun5;rm -rf /"}, invalidInterfaceNames...)
	for _, name := range tests {
		if err := ValidateInterfaceName(name); err == nil {
			t.Errorf("expected %q to be rejected as an interface name", name)
		}
	}
}

func TestValidateInterfaceNameAcceptsValid(t *testing.T) {
	tests := []string{"en0", "utun14", "bridge100", "lo0"}
	for _, name := range tests {
		if err := ValidateInterfaceName(name); err != nil {
			t.Errorf("expected %q to be a valid interface name, got %v", name, err)
		}
	}
}
