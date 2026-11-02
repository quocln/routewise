package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"testing"
)

func (m *MockDaemon) Prefs(uid uint32) (map[string]json.RawMessage, error) {
	m.prefUIDs = append(m.prefUIDs, uid)
	if m.mutateErr != nil {
		return nil, m.mutateErr
	}
	return m.prefs[uid], nil // nil for a user with none: the handler must still answer an object
}

func (m *MockDaemon) SetPref(uid uint32, key string, value json.RawMessage) error {
	m.prefUIDs = append(m.prefUIDs, uid)
	if m.mutateErr != nil {
		return m.mutateErr
	}
	if m.prefs == nil {
		m.prefs = map[uint32]map[string]json.RawMessage{}
	}
	if m.prefs[uid] == nil {
		m.prefs[uid] = map[string]json.RawMessage{}
	}
	if string(value) == "null" {
		delete(m.prefs[uid], key)
		return nil
	}
	m.prefs[uid][key] = value
	return nil
}

func encode(t *testing.T, resp *Response) string {
	t.Helper()
	raw, err := json.Marshal(resp)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func TestPrefsGetAnswersAnObjectForTheCallingPeersUID(t *testing.T) {
	m := &MockDaemon{prefs: map[uint32]map[string]json.RawMessage{
		501: {"launchAtLogin": json.RawMessage(`true`), "lastUpdateCheck": json.RawMessage(`{"at":5}`)},
		502: {"launchAtLogin": json.RawMessage(`false`)},
	}}
	h := NewHandler(m, allowAll{})

	got := encode(t, h.Handle(&Request{JSONRPC: "2.0", Method: MethodPrefsGet, ID: 1}, Peer{UID: 501, Verified: true}))
	if got != `{"jsonrpc":"2.0","result":{"prefs":{"lastUpdateCheck":{"at":5},"launchAtLogin":true}},"id":1}` {
		t.Errorf("prefs.get = %s", got)
	}
	empty := encode(t, h.Handle(&Request{JSONRPC: "2.0", Method: MethodPrefsGet, ID: 1}, Peer{UID: 777, Verified: true}))
	if empty != `{"jsonrpc":"2.0","result":{"prefs":{}},"id":1}` {
		t.Errorf("prefs.get for a user with none = %s, want an empty object, never null", empty)
	}
	if fmt.Sprint(m.prefUIDs) != "[501 777]" {
		t.Errorf("uids = %v, want the peers' own", m.prefUIDs)
	}
}

func TestPrefsUseTheKernelsUIDNeverOneFromTheParams(t *testing.T) {
	m := &MockDaemon{}
	h := NewHandler(m, allowAll{})
	// A request body that tries to name a user, in every place it could.
	req := &Request{JSONRPC: "2.0", Method: MethodPrefsSet, ID: 1,
		Params: json.RawMessage(`{"key":"launchAtLogin","value":true,"uid":0,"peer":{"UID":0},"Peer":{"UID":0}}`)}
	if resp := h.Handle(req, Peer{UID: 501, Verified: true}); resp.Error != nil {
		t.Fatalf("prefs.set: %+v", resp.Error)
	}
	if fmt.Sprint(m.prefUIDs) != "[501]" || len(m.prefs[0]) != 0 {
		t.Errorf("uids = %v, uid 0 prefs = %v: the peer's uid must decide", m.prefUIDs, m.prefs[0])
	}
	if req.peer != (Peer{}) {
		t.Error("Handle must not change the caller's request")
	}
}

func TestRootGetsAndSetsUIDZerosPrefs(t *testing.T) {
	m := &MockDaemon{}
	h := NewHandler(m, allowAll{})
	root := Peer{UID: 0, Verified: true}
	if resp := h.Handle(request(t, MethodPrefsSet, PrefsSetParams{Key: "k", Value: json.RawMessage(`"v"`)}), root); resp.Error != nil {
		t.Fatalf("prefs.set as root: %+v", resp.Error)
	}
	got := encode(t, h.Handle(&Request{JSONRPC: "2.0", Method: MethodPrefsGet, ID: 1}, root))
	if got != `{"jsonrpc":"2.0","result":{"prefs":{"k":"v"}},"id":1}` {
		t.Errorf("prefs.get as root = %s", got)
	}
	if len(m.prefs[501]) != 0 {
		t.Error("root's prefs must not land under another uid")
	}
}

func TestPrefsSetStoresAnyJSONAndNullDeletes(t *testing.T) {
	m := &MockDaemon{}
	h := NewHandler(m, allowAll{})
	for _, value := range []string{`true`, `42`, `"text"`, `[1,2]`, `{"a":{"b":null}}`} {
		resp := h.Handle(&Request{JSONRPC: "2.0", Method: MethodPrefsSet, ID: 1,
			Params: json.RawMessage(`{"key":"k","value":` + value + `}`)}, consolePeer)
		if resp.Error != nil || encode(t, resp) != `{"jsonrpc":"2.0","result":{"success":true},"id":1}` {
			t.Fatalf("value %s: %s", value, encode(t, resp))
		}
		if string(m.prefs[501]["k"]) != value {
			t.Errorf("stored %s, want %s", m.prefs[501]["k"], value)
		}
	}
	resp := h.Handle(&Request{JSONRPC: "2.0", Method: MethodPrefsSet, ID: 1,
		Params: json.RawMessage(`{"key":"k","value":null}`)}, consolePeer)
	if resp.Error != nil || len(m.prefs[501]) != 0 {
		t.Errorf("null must reach the daemon as a delete: %+v, prefs %v", resp.Error, m.prefs[501])
	}
}

func TestPrefsSetRejectsAMissingKeyOrValueAndBadParams(t *testing.T) {
	m := &MockDaemon{}
	h := NewHandler(m, allowAll{})
	for _, params := range []string{`{"value":1}`, `{"key":"","value":1}`, `{"key":"k"}`, `{}`, `[1]`, `"x"`, `{"key":5,"value":1}`} {
		resp := h.Handle(&Request{JSONRPC: "2.0", Method: MethodPrefsSet, ID: 1, Params: json.RawMessage(params)}, consolePeer)
		if resp.Error == nil || resp.Error.Code != ErrCodeInvalidPar {
			t.Errorf("params %s: %+v, want invalid params", params, resp)
		}
	}
	if resp := h.Handle(&Request{JSONRPC: "2.0", Method: MethodPrefsSet, ID: 1}, consolePeer); resp.Error == nil || resp.Error.Code != ErrCodeInvalidPar {
		t.Errorf("no params: %+v", resp)
	}
	if len(m.prefUIDs) != 0 {
		t.Errorf("a rejected request reached the daemon: %v", m.prefUIDs)
	}
}

func TestPrefsDaemonRejectionIsInvalidParamsAndFailureIsAServerError(t *testing.T) {
	h := NewHandler(&MockDaemon{mutateErr: fmt.Errorf("%w: at most 64 keys per user", ErrRejected)}, allowAll{})
	resp := h.Handle(request(t, MethodPrefsSet, PrefsSetParams{Key: "k", Value: json.RawMessage(`1`)}), consolePeer)
	if resp.Error == nil || resp.Error.Code != ErrCodeInvalidPar {
		t.Errorf("rejection: %+v", resp)
	}
	h = NewHandler(&MockDaemon{mutateErr: errors.New("disk")}, allowAll{})
	resp = h.Handle(&Request{JSONRPC: "2.0", Method: MethodPrefsGet, ID: 1}, consolePeer)
	if resp.Error == nil || resp.Error.Code != ErrCodeServer {
		t.Errorf("failure: %+v", resp)
	}
}

func TestPrefsMethodsRefuseAnUnverifiedOrDeniedPeer(t *testing.T) {
	for _, method := range []string{MethodPrefsGet, MethodPrefsSet} {
		m := &MockDaemon{}
		h := NewHandler(m, denyAll{})
		resp := h.Handle(request(t, method, PrefsSetParams{Key: "k", Value: json.RawMessage(`1`)}), Peer{UID: 501})
		if resp.Error == nil || resp.Error.Code != ErrCodeUnauthorized || len(m.prefUIDs) != 0 {
			t.Errorf("%s: %+v, daemon calls %v", method, resp, m.prefUIDs)
		}
	}
}
