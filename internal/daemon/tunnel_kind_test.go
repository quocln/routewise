package daemon

import (
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/quocln/routewise/internal/api"
	"github.com/quocln/routewise/internal/config"
)

// Every kind a profile may have needs an implementation, and nothing else may
// be registered: a kind added to config without one would fail at connect time.
func TestRegistryKeysAreConfigsKnownKinds(t *testing.T) {
	var keys []string
	for k := range tunnelKinds {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	known := config.ProfileKinds()
	slices.Sort(known)
	if !slices.Equal(keys, known) {
		t.Fatalf("registry kinds = %v, config kinds = %v", keys, known)
	}
}

func TestKindsKeepTheirSecretFieldsApart(t *testing.T) {
	if got, err := secretForKind("wireguard", "conf text", ""); err != nil || got != "conf text" {
		t.Errorf("wireguard secret = %q, %v", got, err)
	}
	if got, err := secretForKind("outline", "", "ss://key"); err != nil || got != "ss://key" {
		t.Errorf("outline secret = %q, %v", got, err)
	}
	if _, err := secretForKind("wireguard", "", "ss://key"); err == nil || !strings.Contains(err.Error(), "wireguardConfig") {
		t.Errorf("a WireGuard profile given an access key = %v", err)
	}
	if _, err := secretForKind("outline", "conf text", ""); err == nil || !strings.Contains(err.Error(), "accessKey") {
		t.Errorf("an Outline profile given a .conf = %v", err)
	}
	if _, err := secretForKind("future", "", ""); err == nil {
		t.Error("an unknown kind must be rejected")
	}
}

func TestKindsDescribeThemselves(t *testing.T) {
	for kind, want := range map[string]string{"wireguard": "WireGuard", "outline": "Outline"} {
		if got := tunnelKinds[kind].displayName(); got != want {
			t.Errorf("%s display name = %q, want %q", kind, got, want)
		}
	}
	if p := healthPolicyFor("wireguard"); p.interval != wgCheckInterval || p.failures != 1 {
		t.Errorf("wireguard health policy = %+v", p)
	}
	if p := healthPolicyFor("outline"); p.interval != 30*time.Second || p.failures != 3 {
		t.Errorf("outline health policy = %+v", p)
	}
	if p := healthPolicyFor("future"); p.interval <= 0 || p.failures < 1 {
		t.Errorf("an unknown kind needs a usable health policy, got %+v", p)
	}
	if tunnelKinds["wireguard"].needsSyntheticAddress() || !tunnelKinds["outline"].needsSyntheticAddress() {
		t.Error("only Outline needs a synthetic interface address")
	}
}

func TestSecretTokensCoverTheWholeSecretAndItsSensitiveParts(t *testing.T) {
	wg := secretTokens("wireguard", wireGuardConf("vpn.example.com:51820"))
	for _, want := range []string{wgPrivateKeyText, wgPresharedText} {
		if !slices.Contains(wg, want) {
			t.Errorf("WireGuard tokens lack %q", want)
		}
	}
	outline := secretTokens("outline", outlineAccessKey("203.0.113.5"))
	if !slices.Contains(outline, outlinePassword) {
		t.Error("Outline tokens lack the password")
	}
	// A kind the registry lacks still has its whole secret scrubbed.
	if got := redact("failed with hunter2hunter2", "future", "hunter2hunter2"); strings.Contains(got, "hunter2") {
		t.Errorf("redact left the secret: %q", got)
	}
}

func TestOnlyKindsThatReserveAddressesReadStoredSecrets(t *testing.T) {
	read := false
	load := func() (string, error) { read = true; return wireGuardConf("vpn.example.com:51820"), nil }
	if got := tunnelKinds["outline"].reservedAddrs(load); len(got) != 0 || read {
		t.Errorf("Outline reserved %v and read a secret = %v", got, read)
	}
	if got := tunnelKinds["wireguard"].reservedAddrs(load); len(got) != 1 || got[0].String() != "10.8.0.2" || !read {
		t.Errorf("WireGuard reserved %v", got)
	}
}

func TestUniquenessIsEnforcedForWireGuardOnly(t *testing.T) {
	mine := wireGuardConfWith(wgPrivateKeyText, "10.8.0.2/24")
	same := func() []profileSecret { return []profileSecret{{name: "Other", secret: mine}} }
	if err := tunnelKinds["wireguard"].checkUnique(mine, same); err == nil || !strings.Contains(err.Error(), "Other") {
		t.Errorf("a repeated WireGuard key = %v, want a refusal naming the other profile", err)
	}
	if err := tunnelKinds["wireguard"].checkUnique(mine, func() []profileSecret { return nil }); err != nil {
		t.Errorf("no other profile: %v", err)
	}
	called := false
	if err := tunnelKinds["outline"].checkUnique("ss://x", func() []profileSecret { called = true; return nil }); err != nil || called {
		t.Errorf("Outline must accept without looking at other profiles (err=%v, looked=%v)", err, called)
	}
	if err := tunnelKinds["wireguard"].checkUnique(mine, same); !strings.Contains(err.Error(), "profile Other") || !isRejected(err) {
		t.Errorf("refusal = %v", err)
	}
}

func isRejected(err error) bool {
	return err != nil && strings.Contains(err.Error(), api.ErrRejected.Error())
}

func TestSOCKS5Secret(t *testing.T) {
	if got, err := secretForKind("socks5", "", "socks5://h.example.com:1080"); err != nil || got != "socks5://h.example.com:1080" {
		t.Errorf("socks5 secret = %q, %v", got, err)
	}
	if _, err := secretForKind("socks5", "conf text", ""); err == nil || !strings.Contains(err.Error(), "accessKey") {
		t.Errorf("a SOCKS5 profile given a .conf = %v", err)
	}
	if tunnelKinds["socks5"].displayName() != "SOCKS5" {
		t.Error("wrong display name")
	}

	dns, label, err := validateSecret("socks5", "socks5://u:secret-pass@proxy.example.com:1080")
	if err != nil || label != "proxy.example.com" || len(dns) != 1 {
		t.Errorf("validateSecret = %v, %q, %v", dns, label, err)
	}
	if _, _, err := validateSecret("socks5", "http://u:secret-pass@proxy.example.com:1080"); err == nil {
		t.Error("another scheme was accepted")
	} else if strings.Contains(err.Error(), "secret-pass") {
		t.Errorf("the error repeats the password: %v", err)
	}
}

func TestSOCKS5RedactsTheCredentialsHoweverTheyAreWritten(t *testing.T) {
	const secret = "socks5://proxy-user:pass%40word1@proxy.example.com:1080"
	text := "failed for " + secret + " with proxy-user pass@word1 proxy-user:pass%40word1"
	got := redact(text, "socks5", secret)
	for _, leak := range []string{"proxy-user", "pass@word1", "pass%40word1"} {
		if strings.Contains(got, leak) {
			t.Errorf("redact left %q in %q", leak, got)
		}
	}
}

// A route through the LAN to 127.0.0.1 would break a proxy on this machine, and with
// no server known it cannot take the default VPN role, whose routes would swallow what
// the proxy connects onward to.
func TestTransportOfAProxyOnThisMachine(t *testing.T) {
	for _, tt := range []struct {
		server    string
		endpoints int
		ipv6      bool
	}{
		{"203.0.113.9", 1, false},
		{"192.168.1.5", 1, false},
		{"127.0.0.1", 0, false},
		{"::1", 0, false},
		{"2001:db8::1", 0, true},
		{"::ffff:203.0.113.9", 1, false},
	} {
		addr := netip.MustParseAddr(tt.server)
		if got := proxyEndpoints(addr); len(got) != tt.endpoints {
			t.Errorf("%s endpoints = %v", tt.server, got)
		}
		if got := proxyIPv6Transport(addr); got != tt.ipv6 {
			t.Errorf("%s IPv6 transport = %v", tt.server, got)
		}
	}
}

func TestHTTPProxySecret(t *testing.T) {
	if got, err := secretForKind("http", "", "http://h.example.com:8080"); err != nil || got != "http://h.example.com:8080" {
		t.Errorf("http secret = %q, %v", got, err)
	}
	if _, err := secretForKind("http", "conf text", ""); err == nil || !strings.Contains(err.Error(), "accessKey") {
		t.Errorf("an HTTP proxy profile given a .conf = %v", err)
	}
	dns, label, err := validateSecret("http", "http://u:secret-pass@proxy.example.com:8080")
	if err != nil || label != "proxy.example.com" || len(dns) != 1 {
		t.Errorf("validateSecret = %v, %q, %v", dns, label, err)
	}
	for _, other := range []string{"socks5://u:secret-pass@proxy.example.com:1080", "https://u:secret-pass@proxy.example.com:8080"} {
		if _, _, err := validateSecret("http", other); err == nil {
			t.Errorf("%s was accepted", other)
		} else if strings.Contains(err.Error(), "secret-pass") {
			t.Errorf("the error repeats the password: %v", err)
		}
	}
	if got := redact("failed with secret-pass", "http", "http://proxy-user:secret-pass@proxy.example.com:8080"); strings.Contains(got, "secret-pass") {
		t.Errorf("redact left the password in %q", got)
	}
}
