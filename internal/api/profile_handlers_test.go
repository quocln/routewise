package api

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func (m *MockDaemon) ProfilesList() []ProfileInfo { return m.profiles }

func (m *MockDaemon) ProfileImport(p ProfileImportParams) (string, error) {
	m.profileCalls = append(m.profileCalls, "import")
	m.profileImport = p
	if m.mutateErr != nil {
		return "", m.mutateErr
	}
	return "a1b2c3d4", nil
}

func (m *MockDaemon) ProfileUpdate(p ProfileUpdateParams) error {
	m.profileCalls = append(m.profileCalls, "update")
	m.profileUpdate = p
	return m.mutateErr
}

func (m *MockDaemon) ProfileRemove(id string) error {
	m.profileCalls = append(m.profileCalls, "remove:"+id)
	return m.mutateErr
}

func (m *MockDaemon) ProfileConnect(id string) error {
	m.profileCalls = append(m.profileCalls, "connect:"+id)
	return m.mutateErr
}

func (m *MockDaemon) ProfileDisconnect(id string) error {
	m.profileCalls = append(m.profileCalls, "disconnect:"+id)
	return m.mutateErr
}

// wireOf encodes a handler result the way the socket does and returns the JSON.
func wireOf(t *testing.T, resp *Response) string {
	t.Helper()
	if resp.Error != nil {
		t.Fatalf("unexpected error response: %+v", resp.Error)
	}
	raw, err := json.Marshal(resp.Result)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func profileRequest(method string, params any) *Request {
	raw, _ := json.Marshal(params)
	return &Request{JSONRPC: "2.0", Method: method, Params: raw, ID: 1}
}

func TestProfilesListIsABareArray(t *testing.T) {
	m := &MockDaemon{}
	h := NewHandler(m, allowAll{})

	// No profiles: an empty array, never null and never an object.
	if got := wireOf(t, h.Handle(&Request{JSONRPC: "2.0", Method: "profiles.list", ID: 1}, Peer{})); got != "[]" {
		t.Errorf("empty profiles.list = %s, want []", got)
	}

	handshake := int64(1793000000123)
	flows := 3
	m.profiles = []ProfileInfo{
		{ID: "a1b2c3d4", Kind: "wireguard", Name: "Office", AutoConnect: true, DNS: []string{"10.0.0.2"},
			State: ProfileConnected, Interface: "utun5", Server: "vpn.example.com:51820",
			Stats: &ProfileStats{RxBytes: 10, TxBytes: 20, LastHandshakeMs: &handshake}},
		{ID: "e5f6a7b8", Kind: "outline", Name: "Out", DNS: []string{"1.1.1.1"}, State: ProfileDisconnected,
			Stats: &ProfileStats{TCPFlows: &flows, UDPFlows: &flows}},
		{ID: "c0ffee00", Kind: "wireguard", Name: "NoHandshake", DNS: []string{}, State: ProfileConnecting,
			Stats: &ProfileStats{}},
	}
	got := wireOf(t, h.Handle(&Request{JSONRPC: "2.0", Method: "profiles.list", ID: 1}, Peer{}))
	if !strings.HasPrefix(got, "[{") {
		t.Fatalf("profiles.list must be a bare array, got %s", got)
	}
	var entries []map[string]any
	if err := json.Unmarshal([]byte(got), &entries); err != nil || len(entries) != 3 {
		t.Fatalf("profiles.list = %s (%v), want 3 entries", got, err)
	}
	stats := entries[0]["stats"].(map[string]any)
	if v, ok := stats["lastHandshakeMs"].(float64); !ok || int64(v) != handshake {
		t.Errorf("lastHandshakeMs = %v, want the epoch milliseconds %d", stats["lastHandshakeMs"], handshake)
	}
	if _, ok := stats["tcpFlows"]; ok {
		t.Error("a WireGuard profile must not report flow counts")
	}
	if _, ok := entries[2]["stats"].(map[string]any)["lastHandshakeMs"]; ok {
		t.Error("lastHandshakeMs must be omitted when there has been no handshake")
	}
	if entries[1]["stats"].(map[string]any)["tcpFlows"].(float64) != 3 {
		t.Error("an Outline profile reports flow counts")
	}
	for _, e := range entries {
		for _, key := range []string{"id", "kind", "name", "autoConnect", "dns", "state"} {
			if _, ok := e[key]; !ok {
				t.Errorf("entry %v lacks %q", e["id"], key)
			}
		}
	}
}

func TestProfileMutationsAnswerWithAnObject(t *testing.T) {
	m := &MockDaemon{}
	h := NewHandler(m, allowAll{})

	if got := wireOf(t, h.Handle(profileRequest("profiles.import",
		map[string]any{"kind": "outline", "name": "N", "accessKey": "ss://x", "autoConnect": true}), Peer{})); got != `{"id":"a1b2c3d4"}` {
		t.Errorf("profiles.import = %s, want {\"id\":\"a1b2c3d4\"}", got)
	}
	if m.profileImport.Kind != "outline" || !m.profileImport.AutoConnect || m.profileImport.AccessKey != "ss://x" {
		t.Errorf("import params not decoded: %+v", m.profileImport)
	}

	for _, req := range []*Request{
		profileRequest("profiles.update", map[string]any{"id": "a1b2c3d4", "name": "Renamed", "dns": []string{}}),
		profileRequest("profiles.remove", map[string]any{"id": "a1b2c3d4"}),
		profileRequest("profiles.connect", map[string]any{"id": "a1b2c3d4"}),
		profileRequest("profiles.disconnect", map[string]any{"id": "a1b2c3d4"}),
	} {
		if got := wireOf(t, h.Handle(req, Peer{})); got != `{"success":true}` {
			t.Errorf("%s = %s, want {\"success\":true}", req.Method, got)
		}
	}
	if m.profileUpdate.Name == nil || *m.profileUpdate.Name != "Renamed" || m.profileUpdate.DNS == nil || len(*m.profileUpdate.DNS) != 0 {
		t.Errorf("an empty dns list must reach the daemon as set-to-empty: %+v", m.profileUpdate)
	}
	if want := "import update remove:a1b2c3d4 connect:a1b2c3d4 disconnect:a1b2c3d4"; strings.Join(m.profileCalls, " ") != want {
		t.Errorf("calls = %v, want %s", m.profileCalls, want)
	}
}

func TestProfileMutationsNeedAuthorizationAndValidParams(t *testing.T) {
	m := &MockDaemon{}
	for _, method := range []string{"profiles.import", "profiles.update", "profiles.remove", "profiles.connect", "profiles.disconnect"} {
		denied := NewHandler(m, denyAll{}).Handle(profileRequest(method, map[string]any{"id": "x"}), Peer{})
		if denied.Error == nil || denied.Error.Code != ErrCodeUnauthorized {
			t.Errorf("%s must be refused to an unauthorized peer, got %+v", method, denied)
		}
	}
	if len(m.profileCalls) != 0 {
		t.Errorf("an unauthorized call reached the daemon: %v", m.profileCalls)
	}
	h := NewHandler(m, allowAll{})
	for _, method := range []string{"profiles.update", "profiles.remove", "profiles.connect", "profiles.disconnect"} {
		if resp := h.Handle(profileRequest(method, map[string]any{}), Peer{}); resp.Error == nil || resp.Error.Code != ErrCodeInvalidPar {
			t.Errorf("%s without an id must be invalid params, got %+v", method, resp)
		}
	}

	// A rejected request is invalid params, and the error never echoes the secret.
	m.mutateErr = errors.New("boom")
	resp := h.Handle(profileRequest("profiles.import", map[string]any{"kind": "outline", "name": "N", "accessKey": "SECRET-KEY"}), Peer{})
	if resp.Error == nil || strings.Contains(resp.Error.Message, "SECRET-KEY") {
		t.Errorf("import failure = %+v", resp)
	}
	bad := h.Handle(&Request{JSONRPC: "2.0", Method: "profiles.import", Params: json.RawMessage(`{"accessKey":"SECRET-KEY",`), ID: 1}, Peer{})
	if bad.Error == nil || bad.Error.Code != ErrCodeInvalidPar || strings.Contains(bad.Error.Message, "SECRET-KEY") {
		t.Errorf("malformed import = %+v", bad)
	}
}

func TestProfilesListNeedsAuthorizationBecauseItShowsServersAndErrors(t *testing.T) {
	m := &MockDaemon{profiles: []ProfileInfo{{
		ID: "a1b2c3d4", Kind: "outline", Name: "Out", State: ProfileError,
		Server: "203.0.113.9:8388", Error: "could not reach the DNS server through the VPN server",
	}}}
	req := &Request{JSONRPC: "2.0", Method: "profiles.list", ID: 1}

	for name, h := range map[string]*Handler{"denied peer": NewHandler(m, denyAll{}), "no authorizer": NewHandler(m, nil)} {
		resp := h.Handle(req, Peer{})
		if resp.Error == nil || resp.Error.Code != ErrCodeUnauthorized {
			t.Errorf("%s: profiles.list = %+v, want an unauthorized error", name, resp)
		}
		if raw, _ := json.Marshal(resp); strings.Contains(string(raw), "203.0.113.9") || strings.Contains(string(raw), "DNS server") {
			t.Errorf("%s: the refusal leaked profile details: %s", name, raw)
		}
	}
	got := wireOf(t, NewHandler(m, allowAll{}).Handle(req, consolePeer))
	if !strings.Contains(got, "203.0.113.9:8388") {
		t.Errorf("an authorized peer must see the profile, got %s", got)
	}
}
