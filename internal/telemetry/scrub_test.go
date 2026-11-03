package telemetry

import (
	"strings"
	"testing"

	"github.com/quocln/routewise/internal/config"
)

func TestScrubberGenericRules(t *testing.T) {
	s := NewScrubber()
	const r = Redacted
	cases := []struct{ name, in, want string }{
		{"ipv4", "dial 10.20.30.40 failed", "dial " + r + " failed"},
		{"ipv4 port", "dial 10.20.30.40:443 failed", "dial " + r + ":443 failed"},
		{"ipv4 cidr", "route 10.20.0.0/16 added", "route " + r + " added"},
		{"ipv4 twice", "a=1.2.3.4 b=5.6.7.8", "a=" + r + " b=" + r},
		{"not an ipv4", "version 999.1.1.1 and 1.2.3", "version 999.1.1.1 and 1.2.3"},
		{"ipv6", "peer 2001:db8::1 gone", "peer " + r + " gone"},
		{"ipv6 loopback", "listen ::1 ok", "listen " + r + " ok"},
		{"ipv6 bracket port", "dial [2001:db8::8a2e:370:7334]:443", "dial [" + r + "]:443"},
		{"ipv6 zone", "if fe80::1%utun3 up", "if " + r + " up"},
		{"ipv6 cidr", "net fd00:1234::/64 routed", "net " + r + " routed"},
		{"ipv6 after label", "addr:2001:db8::1 end", "addr:" + r + " end"},
		{"ipv6 sentence end", "gateway is 2001:db8::1.", "gateway is " + r + "."},
		{"ipv6 full", "2001:0db8:0000:0000:0000:ff00:0042:8329 x", r + " x"},
		{"ipv4 mapped", "from ::ffff:10.0.0.1 in", "from " + r + " in"},
		{"clock is not an address", "at 12:30:45 today", "at 12:30:45 today"},
		{"mac", "link aa:bb:cc:dd:ee:ff up", "link " + r + " up"},
		{"domain", "lookup vpn.example.com failed", "lookup " + r + " failed"},
		{"domain port", "dial vpn.example.com:8443", "dial " + r + ":8443"},
		{"wildcard", "pattern *.example.com added", "pattern " + r + " added"},
		{"partial wildcard", "pattern qa*.example.com added", "pattern " + r + " added"},
		{"country domain", "host api.example.co.uk down", "host " + r + " down"},
		{"url", "GET https://vpn.corp.example.com:8443/path?x=1", "GET https://" + r + ":8443/path?x=1"},
		{"url userinfo", "https://user:pw@host.example.org/x", r},
		{"email", "mail ops@corp.example.com now", "mail " + r + " now"},
		{"uppercase domain", "LOOKUP VPN.EXAMPLE.COM", "LOOKUP " + r},
		{"internal tld", "resolve db.corp.internal", "resolve " + r},
		{"go file stays", "at socket.go:42 and main.go", "at socket.go:42 and main.go"},
		{"function names stay", "daemon.(*Daemon).Start panics in fmt.Errorf via os.Exit", "daemon.(*Daemon).Start panics in fmt.Errorf via os.Exit"},
		{"package funcs stay", "net.Dial, http.Server, context.DeadlineExceeded", "net.Dial, http.Server, context.DeadlineExceeded"},
		{"home path", "open /Users/alice/Library/x", "open /Users/" + r + "/Library/x"},
		{"wireguard key", "key=" + strings.Repeat("A", 43) + "=", "key=" + r},
		{"outline key", "access ss://Y2hhY2hhMjA6c2VjcmV0@1.2.3.4:8388/?outline=1 ok", "access " + r + " ok"},
		{"socks5 address", "proxy socks5://user:secret@proxy.example.com:1080 ok", "proxy " + r + " ok"},
		{"http proxy address", "proxy http://user:secret@proxy.example.com:8080 ok", "proxy " + r + " ok"},
		{"http url with no login", "see http://example.com/a ok", "see http://" + r + "/a ok"},
		{"http proxy on a name with no dot", "proxy http://user:secret@localhost:8080 ok", "proxy " + r + " ok"},
		{"socks5h address", "proxy SOCKS5H://user:secret@proxy.example.com:1080 ok", "proxy " + r + " ok"},
		{"empty", "", ""},
		{"plain", "tunnel stopped unexpectedly", "tunnel stopped unexpectedly"},
	}
	for _, c := range cases {
		if got := s.String(c.in); got != c.want {
			t.Errorf("%s: String(%q) = %q, want %q", c.name, c.in, got, c.want)
		}
	}
}

func TestScrubberRedactsConfiguredTerms(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Domains = []config.DomainRule{{Pattern: "*.corp.example.com"}, {Pattern: "intranet"}}
	cfg.VPNs = []config.VPNRoute{
		{Client: "/Applications/Acme VPN.app/Contents/MacOS/AcmeVPN", Domains: []config.DomainRule{{Pattern: "wiki.acme.test"}}},
		{Client: "routewise-wireguard:0a1b2c3d"},
	}
	cfg.Profiles = []config.TunnelProfile{{ID: "0a1b2c3d", Kind: config.ProfileKindWireGuard, Name: "Berlin Office"}}

	s := NewScrubber()
	s.SetTerms(TermsFromConfig(cfg))
	cases := map[string]string{
		"profile Berlin Office failed":                             "profile " + Redacted + " failed",
		"profile berlin office failed":                             "profile " + Redacted + " failed",
		"client /Applications/Acme VPN.app/Contents/MacOS/AcmeVPN": "client " + Redacted,
		"started AcmeVPN":                                          "started " + Redacted,
		"suffix corp.example.com down":                             "suffix " + Redacted + " down",
		"the intranet is down":                                     "the " + Redacted + " is down",
		"host wiki.corp.example.com down":                          "host " + Redacted + " down",
		"wiki.acme.test unreachable":                               Redacted + " unreachable",
		"routewise-wireguard:0a1b2c3d connected":                   "routewise-wireguard:0a1b2c3d connected",
	}
	for in, want := range cases {
		if got := s.String(in); got != want {
			t.Errorf("String(%q) = %q, want %q", in, got, want)
		}
	}

	// Terms follow the configuration: a removed profile is no longer matched,
	// and a name too short to be meaningful is never matched.
	s.SetTerms([]string{"ab", "  "})
	if got := s.String("Berlin Office ab"); got != "Berlin Office ab" {
		t.Errorf("stale or short terms matched: %q", got)
	}
}

func TestScrubberLongestTermWins(t *testing.T) {
	s := NewScrubber()
	s.SetTerms([]string{"example", "vpn example"})
	if got := s.String("a vpn example b"); got != "a "+Redacted+" b" {
		t.Errorf("got %q", got)
	}
}

func TestScrubberHandlesHostileInput(t *testing.T) {
	s := NewScrubber()
	for _, in := range []string{
		strings.Repeat(":", 5000), strings.Repeat("a:", 3000), strings.Repeat("1.", 5000),
		strings.Repeat("a.", 3000) + "com", "\x00\xff::", "[[[]]]",
	} {
		_ = s.String(in) // must terminate without panicking
	}
}
