package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/quocln/routewise/internal/activity"
	"github.com/quocln/routewise/internal/config"
	"github.com/quocln/routewise/internal/history"
)

// MockDaemon implements DaemonStatus for testing. It stands in for the daemon's
// config ownership: the handler never touches configuration directly.
type MockDaemon struct {
	running       bool
	vpnConnected  bool
	vpnInterface  string
	routes        []RouteEntry
	syncTriggered bool
	scanned       []VPNClient

	degraded       bool
	degradedReason string
	dnsStatus      DNSStatus
	tunnels        []TunnelStatus

	domains  []string
	revision uint64
	// mutateErr, when set, is returned by every mutation.
	mutateErr error

	useVPNDNS                      bool
	allowIPv6                      bool
	defaultVPN, defaultVPNFallback string
	defaultVPNStatus               *DefaultVPNStatus
	pendingVPNs                    []PendingVPN
	allowedClients                 map[string]bool
	events                         []activity.Event
	imported                       *config.Export

	// Access history: the entries AccessList serves and the last query seen.
	access          []history.Entry
	accessQuery     *AccessListParams
	accessCleared   bool
	dnsCacheCleared bool
	dnsCleaned      bool
	historyOn       bool
	historyDays     int
	telemetry       TelemetrySettings

	// App preferences per uid, and the uid of every prefs call the daemon saw.
	prefs    map[uint32]map[string]json.RawMessage
	prefUIDs []uint32

	// Built-in profiles: what ProfilesList serves and the last request each
	// profile method saw.
	profiles      []ProfileInfo
	profileCalls  []string
	profileImport ProfileImportParams
	profileUpdate ProfileUpdateParams
}

func (m *MockDaemon) Settings() Settings {
	return Settings{UseVPNDNS: m.useVPNDNS, AllowIPv6: m.allowIPv6, HistoryEnabled: m.historyOn, HistoryRetentionDays: m.historyDays}
}

func (m *MockDaemon) AccessList(q AccessListParams) (AccessListResult, error) {
	if m.mutateErr != nil {
		return AccessListResult{}, m.mutateErr
	}
	m.accessQuery = &q
	if q.Verdict != "" && q.Verdict != "vpn" && q.Verdict != "direct" && q.Verdict != "other" {
		return AccessListResult{}, fmt.Errorf("%w: bad verdict", ErrRejected)
	}
	var latest int64
	if len(m.access) > 0 {
		latest = m.access[len(m.access)-1].ID
	}
	return AccessListResult{Entries: m.access, LatestID: latest}, nil
}

func (m *MockDaemon) AccessClear() (int64, error) {
	if m.mutateErr != nil {
		return 0, m.mutateErr
	}
	n := int64(len(m.access))
	m.access, m.accessCleared = nil, true
	return n, nil
}

func (m *MockDaemon) Telemetry() TelemetrySettings { return m.telemetry }

func (m *MockDaemon) SetTelemetry(p SetTelemetryParams) error {
	if m.mutateErr != nil {
		return m.mutateErr
	}
	t := &m.telemetry
	if p.DSN != nil {
		if err := config.ValidateDSN(*p.DSN); err != nil {
			return fmt.Errorf("%w: %w", ErrRejected, err)
		}
		t.DSN = *p.DSN
	}
	if p.Errors != nil {
		t.Errors = *p.Errors
	}
	if p.Sessions != nil {
		t.Sessions = *p.Sessions
	}
	if p.Logs != nil {
		t.Logs = *p.Logs
	}
	if p.Traces != nil {
		t.Traces = *p.Traces
	}
	if p.TracesSampleRate != nil {
		if err := config.ValidateTracesSampleRate(*p.TracesSampleRate); err != nil {
			return fmt.Errorf("%w: %w", ErrRejected, err)
		}
		t.TracesSampleRate = *p.TracesSampleRate
	}
	return nil
}

func (m *MockDaemon) SetHistory(enabled *bool, days *int) error {
	if m.mutateErr != nil {
		return m.mutateErr
	}
	if enabled != nil {
		m.historyOn = *enabled
	}
	if days != nil {
		m.historyDays = *days
	}
	return nil
}

func (m *MockDaemon) VPNClients() (*VPNClient, []PendingVPN) { return nil, m.pendingVPNs }
func (m *MockDaemon) Tunnels() []TunnelStatus                { return m.tunnels }

func (m *MockDaemon) Activity(since uint64, limit int, _ time.Duration) (uint64, []activity.Event) {
	var out []activity.Event
	for _, e := range m.events {
		if e.Seq > since {
			out = append(out, e)
		}
	}
	return uint64(len(m.events)), out
}

func (m *MockDaemon) ExportConfig() config.Export {
	return config.NewExport(config.DefaultConfig(), time.Unix(0, 0))
}

func (m *MockDaemon) ImportConfig(e config.Export) (bool, error) {
	if m.mutateErr != nil {
		return false, m.mutateErr
	}
	m.imported = &e
	return false, nil
}

func (m *MockDaemon) CheckHost(host string) (HostCheck, error) {
	return HostCheck{Host: host, Addresses: []HostAddress{{IP: "10.20.30.40", Verdict: "vpn", Interface: "utun6"}}}, nil
}

// rejectedVPNPath is a program the mock refuses, as the daemon refuses anything
// that could never own a tunnel.
const rejectedVPNPath = "/not/a/vpn"

func (m *MockDaemon) ScanVPNClients() []VPNClient { return m.scanned }

func (m *MockDaemon) ResolveVPNClient(path string) (VPNClient, error) {
	if path == rejectedVPNPath {
		return VPNClient{}, fmt.Errorf("%w: not a VPN client", ErrRejected)
	}
	return VPNClient{ID: path + "/tunnel", Name: "Tunnel"}, nil
}

func (m *MockDaemon) SetVPNClientAllowed(id string, allowed bool) error {
	if m.mutateErr != nil {
		return m.mutateErr
	}
	if m.allowedClients == nil {
		m.allowedClients = map[string]bool{}
	}
	m.allowedClients[id] = allowed
	return nil
}

func (m *MockDaemon) SetUseVPNDNS(enabled bool) error {
	if m.mutateErr != nil {
		return m.mutateErr
	}
	m.useVPNDNS = enabled
	return nil
}

func (m *MockDaemon) ClearDNSCache() error {
	if m.mutateErr != nil {
		return m.mutateErr
	}
	m.dnsCacheCleared = true
	return nil
}

func (m *MockDaemon) CleanDNS() (int, error) {
	if m.mutateErr != nil {
		return 0, m.mutateErr
	}
	m.dnsCleaned = true
	return 3, nil
}

func (m *MockDaemon) SetAllowIPv6(allowed bool) error {
	if m.mutateErr != nil {
		return m.mutateErr
	}
	m.allowIPv6 = allowed
	return nil
}

func (m *MockDaemon) SetDefaultVPN(client, fallback *string) error {
	if m.mutateErr != nil {
		return m.mutateErr
	}
	if client != nil {
		m.defaultVPN = *client
	}
	if fallback != nil {
		m.defaultVPNFallback = *fallback
	}
	return nil
}

func (m *MockDaemon) DefaultVPNStatus() *DefaultVPNStatus { return m.defaultVPNStatus }

func (m *MockDaemon) Profile(kind ProfileKind, seconds int) ([]byte, error) {
	if m.mutateErr != nil {
		return nil, m.mutateErr
	}
	return []byte(string(kind)), nil
}

func (m *MockDaemon) IsRunning() bool                              { return m.running }
func (m *MockDaemon) GetVPNConnected() bool                        { return m.vpnConnected }
func (m *MockDaemon) GetVPNInterface() string                      { return m.vpnInterface }
func (m *MockDaemon) GetRouteCount() int                           { return len(m.routes) }
func (m *MockDaemon) GetActiveRoutes() []RouteEntry                { return m.routes }
func (m *MockDaemon) TriggerSync()                                 { m.syncTriggered = true }
func (m *MockDaemon) Degraded() (bool, string)                     { return m.degraded, m.degradedReason }
func (m *MockDaemon) DNSStatus() DNSStatus                         { return m.dnsStatus }
func (m *MockDaemon) ListDomains(string) ([]string, uint64, error) { return m.domains, m.revision, nil }

func (m *MockDaemon) AddDomain(_, pattern string) error {
	if m.mutateErr != nil {
		return m.mutateErr
	}
	m.domains = append(m.domains, pattern)
	m.revision++
	return nil
}

func (m *MockDaemon) RemoveDomain(_, pattern string) error {
	if m.mutateErr != nil {
		return m.mutateErr
	}
	kept := m.domains[:0]
	found := false
	for _, d := range m.domains {
		if d == pattern {
			found = true
			continue
		}
		kept = append(kept, d)
	}
	if !found {
		return fmt.Errorf("%w: domain %q not found", ErrRejected, pattern)
	}
	m.domains = kept
	m.revision++
	return nil
}

func (m *MockDaemon) SetDomains(_ string, patterns []string, expectedRevision uint64) error {
	if m.mutateErr != nil {
		return m.mutateErr
	}
	if expectedRevision != 0 && expectedRevision != m.revision {
		return fmt.Errorf("%w: stale revision", ErrRejected)
	}
	m.domains = patterns
	m.revision++
	return nil
}

// allowAll stands in for an authorizer that has already verified the caller.
type allowAll struct{}

func (allowAll) AllowMutation(Peer) error { return nil }

// denyAll stands in for a caller the authorizer rejects.
type denyAll struct{}

func (denyAll) AllowMutation(Peer) error {
	return fmt.Errorf("%w: test denial", ErrUnauthorized)
}

// consolePeer is a verified caller; the authorizer decides the rest.
var consolePeer = Peer{UID: 501, Verified: true}

func request(t *testing.T, method string, params interface{}) *Request {
	t.Helper()
	raw, err := json.Marshal(params)
	if err != nil {
		t.Fatalf("marshal params: %v", err)
	}
	return &Request{JSONRPC: "2.0", Method: method, Params: raw, ID: 1}
}

func TestAddDomain_Validation(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		wantErr bool
	}{
		{"Valid domain", "example.com", false},
		{"Valid wildcard", "*.example.com", false},
		{"Valid partial-label wildcard", "qa*.example.com", false},
		{"Valid subdomain", "sub.example.com", false},
		{"Empty pattern", "", true},
		{"Invalid pattern", "invalid space.com", true},
		{"Invalid wildcard middle", "test.*.com", true},
		{"Invalid wildcard suffix", "test.com.*", true},
		{"Wildcard over a top-level domain", "*.com", true},
		{"Two wildcards", "*a*.example.com", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			daemon := &MockDaemon{}
			handler := NewHandler(daemon, allowAll{})
			resp := handler.Handle(request(t, "domains.add", AddDomainParams{Pattern: tt.pattern}), consolePeer)

			if tt.wantErr {
				if resp.Error == nil {
					t.Fatalf("expected error for pattern %q, got success", tt.pattern)
				}
				if resp.Error.Code != ErrCodeInvalidPar {
					t.Errorf("expected InvalidParams, got code %d", resp.Error.Code)
				}
				if len(daemon.domains) != 0 {
					t.Errorf("rejected pattern %q must not reach the daemon", tt.pattern)
				}
				return
			}

			if resp.Error != nil {
				t.Fatalf("expected success for pattern %q, got error: %v", tt.pattern, resp.Error)
			}
			if len(daemon.domains) != 1 || daemon.domains[0] != tt.pattern {
				t.Errorf("daemon domains = %v, want [%q]", daemon.domains, tt.pattern)
			}
			if !daemon.syncTriggered {
				t.Error("expected a route sync after a successful mutation")
			}
		})
	}
}

func TestAddDomain_AcceptsIPv4AndCIDREntriesAndRejectsTheRest(t *testing.T) {
	for _, tc := range []struct {
		pattern string
		ok      bool
		message string
	}{
		{"10.20.30.40", true, ""},
		{"10.20.0.0/16", true, ""},
		{"10.20.5.1/16", true, ""}, // normalized by the daemon's store
		{"2001:db8::1", false, "IPv6"},
		{"2001:db8::/32", false, "IPv6"},
		{"10.0.0.0/7", false, "too broad"},
		{"0.0.0.0/8", false, "0.0.0.0/8"},
		{"127.0.0.1", false, "loopback"},
		{"224.0.0.0/4", false, "too broad"},
		{"239.0.0.0/8", false, "multicast"},
		{"169.254.1.0/24", false, "link-local"},
		{"10.20.30.400", false, "valid IPv4"},
	} {
		daemon := &MockDaemon{}
		handler := NewHandler(daemon, allowAll{})
		resp := handler.Handle(request(t, "domains.add", AddDomainParams{Pattern: tc.pattern}), consolePeer)
		if tc.ok {
			if resp.Error != nil || len(daemon.domains) != 1 {
				t.Errorf("%q: error = %v, domains = %v, want it accepted", tc.pattern, resp.Error, daemon.domains)
			}
			continue
		}
		if resp.Error == nil || resp.Error.Code != ErrCodeInvalidPar || !strings.Contains(resp.Error.Message, tc.message) {
			t.Errorf("%q: error = %+v, want InvalidParams mentioning %q", tc.pattern, resp.Error, tc.message)
		}
		if len(daemon.domains) != 0 {
			t.Errorf("rejected entry %q must not reach the daemon", tc.pattern)
		}
	}
}

func TestSetDomains_ValidatesEntriesWithTheSameRules(t *testing.T) {
	daemon := &MockDaemon{}
	handler := NewHandler(daemon, allowAll{})

	resp := handler.Handle(request(t, "domains.set", SetDomainsParams{Patterns: []string{"example.com", "10.20.0.0/16", "10.20.30.40"}}), consolePeer)
	if resp.Error != nil {
		t.Fatalf("a list of domains, an IP and a CIDR must be accepted: %v", resp.Error)
	}

	daemon = &MockDaemon{}
	handler = NewHandler(daemon, allowAll{})
	resp = handler.Handle(request(t, "domains.set", SetDomainsParams{Patterns: []string{"example.com", "10.0.0.0/7"}}), consolePeer)
	if resp.Error == nil || resp.Error.Code != ErrCodeInvalidPar || !strings.Contains(resp.Error.Message, "10.0.0.0/7") {
		t.Fatalf("error = %+v, want the bad entry named", resp.Error)
	}
	if daemon.domains != nil {
		t.Error("a list with a bad entry must not reach the daemon")
	}
}

func TestSetDomains_AnEmptyArrayClearsTheListButAMissingOneIsRejected(t *testing.T) {
	daemon := &MockDaemon{domains: []string{"old.example.com"}}
	handler := NewHandler(daemon, allowAll{})

	resp := handler.Handle(request(t, "domains.set", SetDomainsParams{Patterns: []string{}}), consolePeer)
	if resp.Error != nil {
		t.Fatalf("an empty list must be accepted: %v", resp.Error)
	}
	if len(daemon.domains) != 0 {
		t.Errorf("domains = %v, want the list cleared", daemon.domains)
	}

	daemon = &MockDaemon{domains: []string{"old.example.com"}}
	handler = NewHandler(daemon, allowAll{})
	resp = handler.Handle(request(t, "domains.set", map[string]string{"vpn": ""}), consolePeer)
	if resp.Error == nil || resp.Error.Code != ErrCodeInvalidPar {
		t.Fatalf("error = %+v, want InvalidParams for a request without patterns", resp.Error)
	}
	if len(daemon.domains) != 1 {
		t.Error("a request without patterns must not touch the list")
	}
}

func TestSetDomains_Limit(t *testing.T) {
	daemon := &MockDaemon{}
	handler := NewHandler(daemon, allowAll{})

	// Generate too many domains
	patterns := make([]string, MaxDomainPatterns+1)
	for i := 0; i < len(patterns); i++ {
		// Use unique patterns because duplicate filtering happens before limit check
		patterns[i] = string(rune('a'+(i%26))) + string(rune('a'+(i/26))) + ".example.com"
	}

	resp := handler.Handle(request(t, "domains.set", SetDomainsParams{Patterns: patterns}), consolePeer)

	if resp.Error == nil {
		t.Fatal("expected error for exceeding domain limit, got success")
	}
	if resp.Error.Code != ErrCodeInvalidPar {
		t.Errorf("expected InvalidParams error, got code %d", resp.Error.Code)
	}
	if daemon.domains != nil {
		t.Error("over-limit request must not reach the daemon")
	}
}

func TestSetDomains_StaleRevisionRejected(t *testing.T) {
	daemon := &MockDaemon{domains: []string{"example.com"}, revision: 7}
	handler := NewHandler(daemon, allowAll{})

	resp := handler.Handle(request(t, "domains.set", SetDomainsParams{
		Patterns: []string{"other.example.com"},
		Revision: 6,
	}), consolePeer)

	if resp.Error == nil {
		t.Fatal("expected stale revision to be rejected")
	}
	if resp.Error.Code != ErrCodeInvalidPar {
		t.Errorf("expected InvalidParams for stale revision, got code %d", resp.Error.Code)
	}
	if daemon.domains[0] != "example.com" {
		t.Error("stale write must not replace the domain list")
	}
}

func TestMutation_PersistFailureIsServerError(t *testing.T) {
	daemon := &MockDaemon{mutateErr: errors.New("could not persist configuration: read-only file system")}
	handler := NewHandler(daemon, allowAll{})

	resp := handler.Handle(request(t, "domains.add", AddDomainParams{Pattern: "example.com"}), consolePeer)

	if resp.Error == nil {
		t.Fatal("expected an error when the daemon cannot persist")
	}
	if resp.Error.Code != ErrCodeServer {
		t.Errorf("expected ServerError for a helper-side failure, got code %d", resp.Error.Code)
	}
	if daemon.syncTriggered {
		t.Error("a failed mutation must not trigger a route sync")
	}
}

func TestListDomains_ComesFromDaemon(t *testing.T) {
	daemon := &MockDaemon{domains: []string{"b.example.com", "a.example.com"}}
	handler := NewHandler(daemon, allowAll{})

	resp := handler.Handle(&Request{JSONRPC: "2.0", Method: "domains.list", ID: 1}, consolePeer)
	if resp.Error != nil {
		t.Fatalf("domains.list failed: %v", resp.Error)
	}

	domains, ok := resp.Result.([]Domain)
	if !ok {
		t.Fatalf("unexpected result type %T", resp.Result)
	}
	if len(domains) != 2 || domains[0].Pattern != "a.example.com" {
		t.Errorf("expected alphabetically sorted domains, got %v", domains)
	}
}

func TestMutations_RequireAuthorization(t *testing.T) {
	mutations := []struct {
		method string
		params interface{}
	}{
		{"domains.add", AddDomainParams{Pattern: "example.com"}},
		{"domains.remove", RemoveDomainParams{Pattern: "example.com"}},
		{"domains.set", SetDomainsParams{Patterns: []string{"example.com"}}},
	}

	for _, m := range mutations {
		t.Run(m.method, func(t *testing.T) {
			daemon := &MockDaemon{domains: []string{"example.com"}}
			handler := NewHandler(daemon, denyAll{})

			resp := handler.Handle(request(t, m.method, m.params), consolePeer)

			if resp.Error == nil {
				t.Fatalf("%s must be refused for an unauthorized peer", m.method)
			}
			if resp.Error.Code != ErrCodeUnauthorized {
				t.Errorf("expected Unauthorized, got code %d", resp.Error.Code)
			}
			if len(daemon.domains) != 1 || daemon.domains[0] != "example.com" {
				t.Errorf("a denied request must not change domains, got %v", daemon.domains)
			}
			if daemon.syncTriggered {
				t.Error("a denied request must not trigger a route sync")
			}
		})
	}
}

func TestReads_DoNotRequireAuthorization(t *testing.T) {
	reads := []string{"status.get", "domains.list", "routes.list"}

	for _, method := range reads {
		t.Run(method, func(t *testing.T) {
			daemon := &MockDaemon{running: true}
			handler := NewHandler(daemon, denyAll{})

			resp := handler.Handle(&Request{JSONRPC: "2.0", Method: method, ID: 1}, Peer{})
			if resp.Error != nil {
				t.Fatalf("%s must stay readable, got error: %v", method, resp.Error)
			}
		})
	}
}

func TestMutations_NilAuthorizerFailsClosed(t *testing.T) {
	daemon := &MockDaemon{domains: []string{"example.com"}}
	handler := NewHandler(daemon, nil)

	resp := handler.Handle(request(t, "domains.add", AddDomainParams{Pattern: "other.example.com"}), consolePeer)

	if resp.Error == nil || resp.Error.Code != ErrCodeUnauthorized {
		t.Fatalf("a handler wired without an authorizer must deny mutations, got %+v", resp.Error)
	}
	if len(daemon.domains) != 1 {
		t.Errorf("domains changed despite a missing authorizer: %v", daemon.domains)
	}
}

func TestGetStatus_ReportsDegradedAndDNSState(t *testing.T) {
	daemon := &MockDaemon{
		running:        true,
		vpnConnected:   true,
		vpnInterface:   "utun4",
		degraded:       true,
		degradedReason: "route ownership unverified",
		dnsStatus: DNSStatus{
			DomainCount:     4,
			WildcardDomains: []string{"corp.example.com"},
			VPNDNSServers:   []string{"10.0.0.2"},
		},
	}
	handler := NewHandler(daemon, allowAll{})

	resp := handler.Handle(&Request{JSONRPC: "2.0", Method: "status.get", ID: 1}, consolePeer)
	if resp.Error != nil {
		t.Fatalf("status.get failed: %v", resp.Error)
	}

	status, ok := resp.Result.(StatusResult)
	if !ok {
		t.Fatalf("unexpected result type %T", resp.Result)
	}
	if !status.VPNConnected || status.VPNInterface != "utun4" {
		t.Errorf("vpn = %v/%q, want connected on utun4", status.VPNConnected, status.VPNInterface)
	}
	if !status.Degraded || status.DegradedReason != "route ownership unverified" {
		t.Errorf("degraded = %v/%q, want true with a reason", status.Degraded, status.DegradedReason)
	}
	if status.DomainCount != 4 {
		t.Errorf("domainCount = %d, want 4", status.DomainCount)
	}
	if len(status.WildcardDomains) != 1 || status.WildcardDomains[0] != "corp.example.com" {
		t.Errorf("wildcardDomains = %v, want [corp.example.com]", status.WildcardDomains)
	}
	if len(status.VPNDNSServers) != 1 || status.VPNDNSServers[0] != "10.0.0.2" {
		t.Errorf("vpnDnsServers = %v, want [10.0.0.2]", status.VPNDNSServers)
	}
}

func TestGetStatus_ListsEveryManagedTunnel(t *testing.T) {
	daemon := &MockDaemon{
		running:      true,
		vpnConnected: true,
		vpnInterface: "utun4",
		tunnels: []TunnelStatus{
			{Interface: "utun4", Client: VPNClient{ID: "/a/wg", Name: "WireGuard"}, RouteCount: 3, VPNDNSServers: []string{"10.0.0.2"}},
			{Interface: "utun7", Client: VPNClient{ID: "/a/aws", Name: "AWS VPN Client"}, RouteCount: 1},
		},
	}
	handler := NewHandler(daemon, allowAll{})

	resp := handler.Handle(&Request{JSONRPC: "2.0", Method: "status.get", ID: 1}, consolePeer)
	status, ok := resp.Result.(StatusResult)
	if !ok {
		t.Fatalf("unexpected result type %T", resp.Result)
	}
	if len(status.Tunnels) != 2 || status.Tunnels[0].Interface != "utun4" || status.Tunnels[1].Client.Name != "AWS VPN Client" {
		t.Fatalf("tunnels = %+v, want both tunnels in priority order", status.Tunnels)
	}

	raw, err := json.Marshal(status)
	if err != nil {
		t.Fatal(err)
	}
	var wire struct {
		Tunnels []struct {
			Interface     string `json:"interface"`
			Client        struct{ ID, Name string }
			RouteCount    int      `json:"routeCount"`
			VPNDNSServers []string `json:"vpnDnsServers"`
		} `json:"tunnels"`
	}
	if err := json.Unmarshal(raw, &wire); err != nil || len(wire.Tunnels) != 2 || wire.Tunnels[0].RouteCount != 3 || wire.Tunnels[0].VPNDNSServers[0] != "10.0.0.2" {
		t.Fatalf("wire form %s does not match the documented tunnels contract (err %v)", raw, err)
	}

	noTunnels, _ := json.Marshal(StatusResult{})
	if strings.Contains(string(noTunnels), "tunnels") {
		t.Errorf("tunnels must be omitted when none are managed, got %s", noTunnels)
	}
}

func TestProviderMethodIsGone(t *testing.T) {
	handler := NewHandler(&MockDaemon{}, allowAll{})
	resp := handler.Handle(request(t, "routing.provider.set", map[string]string{"provider": "aws"}), consolePeer)
	if resp.Error == nil || resp.Error.Code != ErrCodeMethodNF {
		t.Fatalf("routing.provider.set must be an unknown method, got %+v", resp.Error)
	}
}

func TestSettingsSetChangesUseVPNDNS(t *testing.T) {
	daemon := &MockDaemon{}
	handler := NewHandler(daemon, allowAll{})
	enabled := true

	resp := handler.Handle(request(t, "settings.set", SetSettingsParams{UseVPNDNS: &enabled}), consolePeer)
	if resp.Error != nil {
		t.Fatalf("settings.set: %v", resp.Error.Message)
	}
	if !daemon.useVPNDNS {
		t.Fatal("settings.set must reach the daemon")
	}
	if got, ok := resp.Result.(Settings); !ok || !got.UseVPNDNS {
		t.Fatalf("result = %#v, want the settings now in effect", resp.Result)
	}

	resp = handler.Handle(&Request{JSONRPC: "2.0", Method: "settings.get", ID: 2}, consolePeer)
	if got, ok := resp.Result.(Settings); !ok || !got.UseVPNDNS {
		t.Fatalf("settings.get = %#v, want useVpnDns true", resp.Result)
	}
}

func TestSettingsSetChangesAllowIPv6(t *testing.T) {
	daemon := &MockDaemon{}
	handler := NewHandler(daemon, allowAll{})
	allowed := true

	resp := handler.Handle(request(t, "settings.set", SetSettingsParams{AllowIPv6: &allowed}), consolePeer)
	if resp.Error != nil {
		t.Fatalf("settings.set: %v", resp.Error.Message)
	}
	if !daemon.allowIPv6 {
		t.Fatal("settings.set must reach the daemon")
	}
	if got, ok := resp.Result.(Settings); !ok || !got.AllowIPv6 {
		t.Fatalf("result = %#v, want allowIpv6 true", resp.Result)
	}
	resp = handler.Handle(&Request{JSONRPC: "2.0", Method: "settings.get", ID: 2}, consolePeer)
	if got, ok := resp.Result.(Settings); !ok || !got.AllowIPv6 {
		t.Fatalf("settings.get = %#v, want allowIpv6 true", resp.Result)
	}
	data, err := json.Marshal(resp.Result)
	if err != nil || !strings.Contains(string(data), `"allowIpv6":true`) {
		t.Fatalf("settings JSON = %s, want the allowIpv6 key (%v)", data, err)
	}
	// Only allowIpv6 in a request is a valid change, and a refused write
	// surfaces its error.
	daemon.mutateErr = ErrRejected
	resp = handler.Handle(request(t, "settings.set", SetSettingsParams{AllowIPv6: &allowed}), consolePeer)
	if resp.Error == nil {
		t.Fatal("a failed change must be reported")
	}
}

func TestSettingsSetRequiresAuthorization(t *testing.T) {
	daemon := &MockDaemon{}
	handler := NewHandler(daemon, denyAll{})
	enabled := true

	resp := handler.Handle(request(t, "settings.set", SetSettingsParams{UseVPNDNS: &enabled}), consolePeer)
	if resp.Error == nil || resp.Error.Code != ErrCodeUnauthorized {
		t.Fatalf("expected an authorization error, got %#v", resp.Error)
	}
	if daemon.useVPNDNS {
		t.Fatal("a denied caller must not change settings")
	}
}

func TestSettingsSetWithoutAnySettingIsRejected(t *testing.T) {
	handler := NewHandler(&MockDaemon{}, allowAll{})

	resp := handler.Handle(request(t, "settings.set", map[string]any{}), consolePeer)
	if resp.Error == nil || resp.Error.Code != ErrCodeInvalidPar {
		t.Fatalf("expected invalid params, got %#v", resp.Error)
	}
}

func TestStatusReportsAVPNWaitingForApproval(t *testing.T) {
	pending := PendingVPN{Interface: "utun6", Client: VPNClient{ID: "/Applications/WireGuard.app/x", Name: "WireGuard"}}
	handler := NewHandler(&MockDaemon{running: true, pendingVPNs: []PendingVPN{pending}}, allowAll{})

	resp := handler.Handle(&Request{JSONRPC: "2.0", Method: "status.get", ID: 1}, consolePeer)
	status, ok := resp.Result.(StatusResult)
	if !ok || status.PendingVPN == nil || status.PendingVPN.Client.Name != "WireGuard" {
		t.Fatalf("status = %#v, want the pending WireGuard tunnel", resp.Result)
	}
	if len(status.PendingVPNs) != 1 {
		t.Errorf("pendingVpns = %v, want the one tunnel listed too", status.PendingVPNs)
	}
}

func TestStatusReportsEveryPendingVPNAndKeepsTheFirstForCompatibility(t *testing.T) {
	pending := []PendingVPN{
		{Interface: "utun6", Client: VPNClient{ID: "/a/wg", Name: "WireGuard"}},
		{Interface: "utun8", Client: VPNClient{ID: "/b/ovpn", Name: "OpenVPN"}},
	}
	handler := NewHandler(&MockDaemon{running: true, pendingVPNs: pending}, allowAll{})

	resp := handler.Handle(&Request{JSONRPC: "2.0", Method: "status.get", ID: 1}, consolePeer)
	status, ok := resp.Result.(StatusResult)
	if !ok || len(status.PendingVPNs) != 2 || status.PendingVPNs[1].Interface != "utun8" {
		t.Fatalf("status = %#v, want both pending tunnels", resp.Result)
	}
	if status.PendingVPN == nil || status.PendingVPN.Interface != "utun6" {
		t.Errorf("pendingVpn = %+v, want the first, for clients that read one", status.PendingVPN)
	}

	raw, err := json.Marshal(status)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{`"pendingVpn":`, `"pendingVpns":`} {
		if !strings.Contains(string(raw), key) {
			t.Errorf("status JSON %s lacks %s", raw, key)
		}
	}
	if none, _ := json.Marshal(StatusResult{}); strings.Contains(string(none), "pendingVpns") {
		t.Errorf("an empty list must be omitted: %s", none)
	}
}

func TestVPNSetAllowedRequiresAuthorizationAndAClient(t *testing.T) {
	daemon := &MockDaemon{}
	params := SetVPNClientParams{ClientID: "/Applications/WireGuard.app/x", Allowed: true}

	if resp := NewHandler(daemon, denyAll{}).Handle(request(t, "vpn.setAllowed", params), consolePeer); resp.Error == nil || resp.Error.Code != ErrCodeUnauthorized {
		t.Fatalf("expected an authorization error, got %#v", resp.Error)
	}
	if daemon.allowedClients["/Applications/WireGuard.app/x"] {
		t.Fatal("a denied caller must not change the allowlist")
	}

	handler := NewHandler(daemon, allowAll{})
	if resp := handler.Handle(request(t, "vpn.setAllowed", SetVPNClientParams{Allowed: true}), consolePeer); resp.Error == nil || resp.Error.Code != ErrCodeInvalidPar {
		t.Fatalf("expected invalid params without a client id, got %#v", resp.Error)
	}
	if resp := handler.Handle(request(t, "vpn.setAllowed", params), consolePeer); resp.Error != nil {
		t.Fatalf("vpn.setAllowed: %v", resp.Error.Message)
	}
	if !daemon.allowedClients["/Applications/WireGuard.app/x"] {
		t.Fatal("the client must reach the allowlist")
	}
}

func TestActivityListNeedsAuthorizationAndPagesBySequence(t *testing.T) {
	daemon := &MockDaemon{events: []activity.Event{
		{Seq: 1, Kind: activity.KindDNS, Name: "a.example.com"},
		{Seq: 2, Kind: activity.KindRouteAdded, Name: "b.example.com"},
	}}

	if resp := NewHandler(daemon, denyAll{}).Handle(request(t, "activity.list", ActivityParams{}), consolePeer); resp.Error == nil || resp.Error.Code != ErrCodeUnauthorized {
		t.Fatalf("the lookup history is private; expected an authorization error, got %#v", resp.Error)
	}

	resp := NewHandler(daemon, allowAll{}).Handle(request(t, "activity.list", ActivityParams{Since: 1}), consolePeer)
	result, ok := resp.Result.(ActivityResult)
	if !ok || result.Latest != 2 || len(result.Events) != 1 || result.Events[0].Name != "b.example.com" {
		t.Fatalf("activity.list = %#v, want only the event after sequence 1", resp.Result)
	}
}

func TestRoutesCheckRequiresAHost(t *testing.T) {
	handler := NewHandler(&MockDaemon{}, allowAll{})
	if resp := handler.Handle(request(t, "routes.check", CheckHostParams{}), consolePeer); resp.Error == nil || resp.Error.Code != ErrCodeInvalidPar {
		t.Fatalf("expected invalid params, got %#v", resp.Error)
	}
	resp := handler.Handle(request(t, "routes.check", CheckHostParams{Host: "jira.corp.example.com"}), consolePeer)
	if result, ok := resp.Result.(HostCheck); !ok || result.Addresses[0].Verdict != "vpn" {
		t.Fatalf("routes.check = %#v", resp.Result)
	}
}

func TestConfigImportIsAuthorizedAndChecksTheFormat(t *testing.T) {
	daemon := &MockDaemon{}
	good := config.NewExport(config.DefaultConfig(), time.Unix(0, 0))

	if resp := NewHandler(daemon, denyAll{}).Handle(request(t, "config.import", ImportConfigParams{Config: good}), consolePeer); resp.Error == nil || resp.Error.Code != ErrCodeUnauthorized {
		t.Fatalf("expected an authorization error, got %#v", resp.Error)
	}

	handler := NewHandler(daemon, allowAll{})
	bad := good
	bad.Format = "something-else"
	if resp := handler.Handle(request(t, "config.import", ImportConfigParams{Config: bad}), consolePeer); resp.Error == nil || resp.Error.Code != ErrCodeInvalidPar {
		t.Fatalf("expected invalid params for a foreign file, got %#v", resp.Error)
	}
	if resp := handler.Handle(request(t, "config.import", ImportConfigParams{Config: good}), consolePeer); resp.Error != nil || daemon.imported == nil {
		t.Fatalf("import: %#v", resp.Error)
	}
}

func TestAccessListReturnsEntriesAndPassesTheQuery(t *testing.T) {
	at := time.Date(2026, 10, 28, 9, 30, 0, 123000000, time.UTC)
	daemon := &MockDaemon{access: []history.Entry{
		{ID: 7, Time: at, Name: "jira.example.com", IP: "10.0.0.5", Port: 443, Proto: "tcp", Interface: "utun4", VPN: "WireGuard", Verdict: "vpn"},
	}}
	handler := NewHandler(daemon, allowAll{})

	after := int64(3)
	resp := handler.Handle(request(t, "access.list", AccessListParams{AfterID: &after, Search: "jira", Verdict: "vpn", VPN: "WireGuard", Limit: 10, WaitMs: 5000}), consolePeer)
	if resp.Error != nil {
		t.Fatalf("access.list: %v", resp.Error.Message)
	}
	q := daemon.accessQuery
	if q == nil || q.AfterID == nil || *q.AfterID != 3 || q.Search != "jira" || q.Verdict != "vpn" || q.VPN != "WireGuard" || q.Limit != 10 || q.WaitMs != 5000 {
		t.Fatalf("query = %+v, want every parameter passed through", q)
	}

	raw, err := json.Marshal(resp.Result)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"entries":[{"id":7,"time":"2026-10-28T09:30:00.123Z","name":"jira.example.com","ip":"10.0.0.5","port":443,"proto":"tcp","interface":"utun4","vpn":"WireGuard","verdict":"vpn"}],"latestId":7}`
	if string(raw) != want {
		t.Fatalf("wire format =\n%s\nwant\n%s", raw, want)
	}
}

func TestAccessListWireFormatOmitsAbsentNameAndVPNAndNeverReturnsNull(t *testing.T) {
	daemon := &MockDaemon{}
	handler := NewHandler(daemon, allowAll{})
	resp := handler.Handle(&Request{JSONRPC: "2.0", Method: "access.list", ID: 1}, consolePeer) // no params at all
	if resp.Error != nil {
		t.Fatal(resp.Error.Message)
	}
	raw, _ := json.Marshal(resp.Result)
	if string(raw) != `{"entries":[],"latestId":0}` {
		t.Fatalf("empty result = %s, want an empty entries array", raw)
	}

	daemon.access = []history.Entry{{ID: 1, Time: time.Unix(0, 0).UTC(), IP: "1.1.1.1", Port: 80, Proto: "udp", Interface: "en0", Verdict: "direct"}}
	raw, _ = json.Marshal(handler.Handle(&Request{JSONRPC: "2.0", Method: "access.list", ID: 1}, consolePeer).Result)
	if strings.Contains(string(raw), `"name"`) || strings.Contains(string(raw), `"vpn"`) {
		t.Fatalf("entry = %s, want name and vpn omitted when absent", raw)
	}
}

func TestAccessListRejectsABadVerdictAndBadParams(t *testing.T) {
	handler := NewHandler(&MockDaemon{}, allowAll{})
	resp := handler.Handle(request(t, "access.list", map[string]any{"verdict": "maybe"}), consolePeer)
	if resp.Error == nil || resp.Error.Code != ErrCodeInvalidPar {
		t.Fatalf("a bad verdict: %+v, want InvalidParams", resp.Error)
	}
	resp = handler.Handle(&Request{JSONRPC: "2.0", Method: "access.list", Params: json.RawMessage(`{"limit":"many"}`), ID: 1}, consolePeer)
	if resp.Error == nil || resp.Error.Code != ErrCodeInvalidPar {
		t.Fatalf("a mistyped parameter: %+v, want InvalidParams", resp.Error)
	}
}

func TestAccessMethodsRequireAuthorization(t *testing.T) {
	daemon := &MockDaemon{access: []history.Entry{{ID: 1}}}
	handler := NewHandler(daemon, denyAll{})
	for _, method := range []string{"access.list", "access.clear"} {
		resp := handler.Handle(&Request{JSONRPC: "2.0", Method: method, ID: 1}, consolePeer)
		if resp.Error == nil || resp.Error.Code != ErrCodeUnauthorized {
			t.Errorf("%s: %+v, want unauthorized", method, resp.Error)
		}
	}
	if daemon.accessQuery != nil || daemon.accessCleared {
		t.Fatal("a denied caller must not read or clear the history")
	}
	if handler := NewHandler(daemon, nil); handler.Handle(&Request{JSONRPC: "2.0", Method: "access.list", ID: 1}, consolePeer).Error == nil {
		t.Fatal("a nil authorizer must fail closed")
	}
}

func TestDNSMethodsRequireAuthorization(t *testing.T) {
	daemon := &MockDaemon{}
	handler := NewHandler(daemon, denyAll{})
	for _, method := range []string{"dns.clearCache", "dns.clean"} {
		resp := handler.Handle(&Request{JSONRPC: "2.0", Method: method, ID: 1}, consolePeer)
		if resp.Error == nil || resp.Error.Code != ErrCodeUnauthorized {
			t.Errorf("%s: %+v, want unauthorized", method, resp.Error)
		}
	}
	if daemon.dnsCacheCleared || daemon.dnsCleaned {
		t.Fatal("a denied caller must not touch DNS state")
	}
}

func TestDNSCleanReportsHowManyRoutesWereRemoved(t *testing.T) {
	daemon := &MockDaemon{}
	handler := NewHandler(daemon, allowAll{})
	resp := handler.Handle(&Request{JSONRPC: "2.0", Method: "dns.clean", ID: 1}, consolePeer)
	if resp.Error != nil {
		t.Fatal(resp.Error.Message)
	}
	raw, _ := json.Marshal(resp.Result)
	if string(raw) != `{"routesRemoved":3}` || !daemon.dnsCleaned {
		t.Fatalf("result = %s cleaned=%v", raw, daemon.dnsCleaned)
	}
}

func TestDNSClearCacheReportsAFailure(t *testing.T) {
	handler := NewHandler(&MockDaemon{mutateErr: errors.New("flush failed")}, allowAll{})
	resp := handler.Handle(&Request{JSONRPC: "2.0", Method: "dns.clearCache", ID: 1}, consolePeer)
	if resp.Error == nil || resp.Error.Message != "flush failed" {
		t.Fatalf("error = %+v, want the failure passed on", resp.Error)
	}
}

func TestAccessClearReportsHowManyWereDeleted(t *testing.T) {
	daemon := &MockDaemon{access: []history.Entry{{ID: 1}, {ID: 2}, {ID: 3}}}
	handler := NewHandler(daemon, allowAll{})
	resp := handler.Handle(&Request{JSONRPC: "2.0", Method: "access.clear", ID: 1}, consolePeer)
	if resp.Error != nil {
		t.Fatal(resp.Error.Message)
	}
	raw, _ := json.Marshal(resp.Result)
	if string(raw) != `{"deleted":3}` || !daemon.accessCleared {
		t.Fatalf("result = %s cleared=%v", raw, daemon.accessCleared)
	}
}

func TestSettingsSetChangesTheHistorySettings(t *testing.T) {
	daemon := &MockDaemon{historyOn: true, historyDays: 7}
	handler := NewHandler(daemon, allowAll{})

	off, days := false, 30
	resp := handler.Handle(request(t, "settings.set", SetSettingsParams{HistoryEnabled: &off, HistoryRetentionDays: &days}), consolePeer)
	if resp.Error != nil {
		t.Fatal(resp.Error.Message)
	}
	got, ok := resp.Result.(Settings)
	if !ok || got.HistoryEnabled || got.HistoryRetentionDays != 30 {
		t.Fatalf("result = %#v, want history off with 30 days", resp.Result)
	}

	// Each field is optional: a retention alone leaves enabled as it was.
	days = 14
	resp = handler.Handle(request(t, "settings.set", SetSettingsParams{HistoryRetentionDays: &days}), consolePeer)
	if got := resp.Result.(Settings); got.HistoryEnabled || got.HistoryRetentionDays != 14 {
		t.Fatalf("result = %#v", got)
	}

	raw, _ := json.Marshal(daemon.Settings())
	for _, key := range []string{`"historyEnabled":false`, `"historyRetentionDays":14`} {
		if !strings.Contains(string(raw), key) {
			t.Errorf("settings = %s, missing %s", raw, key)
		}
	}
}

func TestSettingsSetRejectsAnOutOfRangeRetentionBeforeChangingAnything(t *testing.T) {
	daemon := &MockDaemon{historyOn: true, historyDays: 7}
	handler := NewHandler(daemon, allowAll{})
	vpnDNS := true
	for _, days := range []int{0, -1, 91} {
		days := days
		resp := handler.Handle(request(t, "settings.set", SetSettingsParams{UseVPNDNS: &vpnDNS, HistoryRetentionDays: &days}), consolePeer)
		if resp.Error == nil || resp.Error.Code != ErrCodeInvalidPar {
			t.Errorf("retention %d: %+v, want InvalidParams", days, resp.Error)
		}
	}
	if daemon.useVPNDNS || daemon.historyDays != 7 {
		t.Fatal("a rejected request must change nothing, not even its valid fields")
	}
}

func TestSettingsSetChangesTheDefaultVPN(t *testing.T) {
	daemon := &MockDaemon{}
	handler := NewHandler(daemon, allowAll{})
	client, fallback := "/opt/vpn", "routewise-outline:ab12"

	resp := handler.Handle(request(t, "settings.set", SetSettingsParams{DefaultVPN: &client, DefaultVPNFallback: &fallback}), consolePeer)
	if resp.Error != nil {
		t.Fatalf("settings.set: %v", resp.Error.Message)
	}
	if daemon.defaultVPN != client || daemon.defaultVPNFallback != fallback {
		t.Errorf("daemon got %q, %q", daemon.defaultVPN, daemon.defaultVPNFallback)
	}
}

func TestStatusReportsTheDefaultVPN(t *testing.T) {
	daemon := &MockDaemon{defaultVPNStatus: &DefaultVPNStatus{Client: "/opt/vpn", State: DefaultVPNPrimary, ActiveClient: "VPN", ActiveInterface: "utun7"}}
	handler := NewHandler(daemon, allowAll{})
	resp := handler.Handle(&Request{JSONRPC: "2.0", Method: "status.get", ID: 1}, consolePeer)
	got, ok := resp.Result.(StatusResult)
	if !ok || got.DefaultVPN == nil || got.DefaultVPN.ActiveInterface != "utun7" {
		t.Fatalf("result = %#v", resp.Result)
	}
}

func TestDebugProfileReturnsTheProfile(t *testing.T) {
	handler := NewHandler(&MockDaemon{}, allowAll{})
	resp := handler.Handle(request(t, MethodDebugProfile, ProfileParams{Kind: ProfileHeap, Seconds: 1}), consolePeer)
	if resp.Error != nil {
		t.Fatalf("debug.profile: %v", resp.Error.Message)
	}
	if got, ok := resp.Result.(ProfileResult); !ok || string(got.Data) != "heap" {
		t.Fatalf("result = %#v", resp.Result)
	}
}

func TestVPNScanReturnsWhatTheDaemonFound(t *testing.T) {
	found := []VPNClient{{ID: "/usr/sbin/openvpn", Name: "OpenVPN"}}
	resp := NewHandler(&MockDaemon{scanned: found}, allowAll{}).Handle(request(t, "vpn.scan", nil), consolePeer)
	if resp.Error != nil {
		t.Fatalf("vpn.scan: %v", resp.Error.Message)
	}
	result, ok := resp.Result.(VPNScanResult)
	if !ok || len(result.Clients) != 1 || result.Clients[0] != found[0] {
		t.Errorf("result = %#v", resp.Result)
	}
}

func TestVPNResolve(t *testing.T) {
	handler := NewHandler(&MockDaemon{}, allowAll{})

	resp := handler.Handle(request(t, "vpn.resolve", VPNResolveParams{Path: "/Applications/VPN.app"}), consolePeer)
	if resp.Error != nil {
		t.Fatalf("vpn.resolve: %v", resp.Error.Message)
	}
	if client, ok := resp.Result.(VPNClient); !ok || client.ID != "/Applications/VPN.app/tunnel" {
		t.Errorf("result = %#v", resp.Result)
	}

	resp = handler.Handle(request(t, "vpn.resolve", VPNResolveParams{}), consolePeer)
	if resp.Error == nil || resp.Error.Code != ErrCodeInvalidPar {
		t.Errorf("an empty path = %+v, want invalid params", resp.Error)
	}
	// The reason reaches the user, since it says what to choose instead.
	resp = handler.Handle(request(t, "vpn.resolve", VPNResolveParams{Path: rejectedVPNPath}), consolePeer)
	if resp.Error == nil || resp.Error.Code != ErrCodeInvalidPar || !strings.Contains(resp.Error.Message, "not a VPN client") {
		t.Errorf("a program that is no client = %+v, want the reason as invalid params", resp.Error)
	}
}
