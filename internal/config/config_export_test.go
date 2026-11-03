package config

import (
	"encoding/json"
	"github.com/quocln/routewise/internal/testenv"
	"slices"
	"strings"
	"testing"
	"time"
)

var wireGuard = testenv.Exe("/Applications/WireGuard.app/Contents/PlugIns/WireGuardNetworkExtension.appex/Contents/MacOS/WireGuardNetworkExtension")

func multiVPNConfig() *Config {
	cfg := DefaultConfig()
	cfg.Domains = []DomainRule{{Pattern: "any.example.com"}}
	cfg.VPNs = []VPNRoute{
		{Client: wireGuard, Domains: []DomainRule{{Pattern: "*.corp-a.example.com"}}},
		{Client: testenv.Exe("/opt/homebrew/sbin/openvpn"), Domains: []DomainRule{{Pattern: "jira.corp-b.example.com"}}},
	}
	cfg.DNS.UseVPNDNS = true
	cfg.Routing.AllowIPv6 = true
	return cfg
}

func TestExportRoundTripsTheRoutingConfig(t *testing.T) {
	src := multiVPNConfig()
	data, err := json.Marshal(NewExport(src, time.Unix(0, 0)))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"allowIpv6":true`) {
		t.Fatalf("export = %s, want routing.allowIpv6", data)
	}
	if strings.Contains(string(data), "pid_file") || strings.Contains(string(data), src.Daemon.PidFile) {
		t.Fatal("machine-specific daemon settings must not be exported")
	}

	parsed, err := ParseExport(data)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	base := DefaultConfig()
	base.Daemon.PollInterval = 7
	got, err := parsed.Apply(base)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if got.Daemon.PollInterval != 7 {
		t.Error("the importing machine's daemon settings must be kept")
	}
	if len(got.VPNs) != 2 || got.VPNs[0].Client != wireGuard || got.VPNs[0].Domains[0].Pattern != "*.corp-a.example.com" {
		t.Fatalf("VPNs = %+v, want both clients in order with their domains", got.VPNs)
	}
	if len(got.Domains) != 1 || !got.DNS.UseVPNDNS || !got.Routing.AllowIPv6 {
		t.Fatalf("got %+v, want the Any VPN list and use_vpn_dns kept", got)
	}
}

func TestParseExportRejectsOtherFiles(t *testing.T) {
	cases := map[string]string{
		"not JSON":       "domains:\n  - a.example.com\n",
		"another format": `{"format":"something-else","version":1}`,
		"newer version":  `{"format":"routewise-config","version":99}`,
	}
	for name, data := range cases {
		if _, err := ParseExport([]byte(data)); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestApplyRejectsAnInvalidExport(t *testing.T) {
	e := NewExport(multiVPNConfig(), time.Now())
	e.VPNs[0].Domains = []string{"not a domain"}
	if _, err := e.Apply(DefaultConfig()); err == nil {
		t.Fatal("an invalid pattern must be rejected before anything is replaced")
	}

	e = NewExport(multiVPNConfig(), time.Now())
	e.VPNs[1].Client = "relative/path"
	if _, err := e.Apply(DefaultConfig()); err == nil {
		t.Fatal("a VPN client must be an absolute executable path")
	}
}

func TestNeedsRestart(t *testing.T) {
	a := multiVPNConfig()
	b := a.Clone()
	b.Domains = append(b.Domains, DomainRule{Pattern: "new.example.com"})
	if NeedsRestart(a, b) {
		t.Error("domain changes apply live")
	}
	b.DNS.Servers = []string{"9.9.9.9"}
	if !NeedsRestart(a, b) {
		t.Error("DNS servers are read at start")
	}
}

func TestExportCarriesTheHistorySettings(t *testing.T) {
	cfg := multiVPNConfig()
	cfg.History = HistoryConfig{Enabled: false, RetentionDays: 30}
	data, err := json.Marshal(NewExport(cfg, time.Unix(0, 0)))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"history":{"enabled":false,"retentionDays":30}`) {
		t.Fatalf("export = %s, want history {enabled, retentionDays}", data)
	}
	parsed, err := ParseExport(data)
	if err != nil {
		t.Fatal(err)
	}
	got, err := parsed.Apply(DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	if got.History.Enabled || got.History.RetentionDays != 30 {
		t.Fatalf("History = %+v, want the exported values", got.History)
	}
}

func TestImportOfAnOldExportMeansTheHistoryDefaults(t *testing.T) {
	old := `{"format":"routewise-config","version":1,"exportedAt":"2026-01-01T00:00:00Z",
		"dns":{"servers":["8.8.8.8"],"cacheTtl":300,"useVpnDns":false},"routing":{"mode":"inverted"},
		"domains":["a.example.com"],"vpns":[]}`
	parsed, err := ParseExport([]byte(old))
	if err != nil {
		t.Fatal(err)
	}
	base := DefaultConfig()
	base.History = HistoryConfig{Enabled: false, RetentionDays: 30}
	got, err := parsed.Apply(base)
	if err != nil {
		t.Fatal(err)
	}
	if !got.History.Enabled || got.History.RetentionDays != 7 {
		t.Fatalf("History = %+v, want the defaults (true, 7), not the importing machine's values", got.History)
	}
}

func TestImportRejectsAnOutOfRangeRetention(t *testing.T) {
	e := NewExport(multiVPNConfig(), time.Unix(0, 0))
	for _, days := range []int{-1, 91, 1000} {
		e.History = &ExportHistory{Enabled: true, RetentionDays: days}
		if _, err := e.Apply(DefaultConfig()); err == nil {
			t.Errorf("retention %d must be rejected", days)
		}
	}
}

func TestExportCarriesTheDefaultVPN(t *testing.T) {
	cfg := DefaultConfig()
	cfg.VPNs = []VPNRoute{{Client: testenv.Exe("/a")}, {Client: testenv.Exe("/b")}}
	cfg.Routing.DefaultVPN, cfg.Routing.DefaultVPNFallback = testenv.Exe("/a"), testenv.Exe("/b")
	cfg.Routing.DefaultVPNExcept = []string{"bank.example.com", "10.20.0.0/16"}

	data, err := json.Marshal(NewExport(cfg, time.Now()))
	if err != nil {
		t.Fatal(err)
	}
	e, err := ParseExport(data)
	if err != nil {
		t.Fatal(err)
	}
	next, err := e.Apply(DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	if next.Routing.DefaultVPN != testenv.Exe("/a") || next.Routing.DefaultVPNFallback != testenv.Exe("/b") {
		t.Errorf("default VPN after import = %q, fallback %q", next.Routing.DefaultVPN, next.Routing.DefaultVPNFallback)
	}
	if !slices.Equal(next.Routing.DefaultVPNExcept, cfg.Routing.DefaultVPNExcept) {
		t.Errorf("exceptions after import = %v, want %v", next.Routing.DefaultVPNExcept, cfg.Routing.DefaultVPNExcept)
	}
}

func TestApplyDefaultsClearsADefaultVPNThatIsNoLongerAllowed(t *testing.T) {
	tests := []struct {
		name                   string
		allowed                []string
		def, fallback          string
		wantDefault, wantFallb string
	}{
		{"both allowed", []string{"/a", "/b"}, "/a", "/b", "/a", "/b"},
		{"default revoked takes the fallback with it", []string{"/b"}, "/a", "/b", "", ""},
		{"fallback revoked", []string{"/a"}, "/a", "/b", "/a", ""},
		{"fallback equal to the default", []string{"/a"}, "/a", "/a", "/a", ""},
		{"fallback with no default", []string{"/b"}, "", "/b", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultConfig()
			for _, id := range tt.allowed {
				cfg.VPNs = append(cfg.VPNs, VPNRoute{Client: id})
			}
			cfg.Routing.DefaultVPN, cfg.Routing.DefaultVPNFallback = tt.def, tt.fallback
			cfg.ApplyDefaults()
			if cfg.Routing.DefaultVPN != tt.wantDefault || cfg.Routing.DefaultVPNFallback != tt.wantFallb {
				t.Errorf("got %q, %q; want %q, %q", cfg.Routing.DefaultVPN, cfg.Routing.DefaultVPNFallback, tt.wantDefault, tt.wantFallb)
			}
		})
	}
}
