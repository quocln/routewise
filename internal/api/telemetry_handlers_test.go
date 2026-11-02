package api

import (
	"encoding/json"
	"strings"
	"testing"
)

const testDSN = "https://abc123@rustrak.example.test/7"

func TestTelemetryGetAnswersEveryKeyAndIsPrivate(t *testing.T) {
	m := &MockDaemon{telemetry: TelemetrySettings{DSN: testDSN, Errors: true, TracesSampleRate: 0.2}}
	got := encode(t, NewHandler(m, allowAll{}).Handle(
		&Request{JSONRPC: "2.0", Method: MethodTelemetryGet, ID: 1}, Peer{UID: 501, Verified: true}))
	want := `{"jsonrpc":"2.0","result":{"dsn":"` + testDSN + `","errors":true,"sessions":false,"logs":false,"traces":false,"tracesSampleRate":0.2},"id":1}`
	if got != want {
		t.Errorf("telemetry.get = %s", got)
	}

	resp := NewHandler(m, denyAll{}).Handle(&Request{JSONRPC: "2.0", Method: MethodTelemetryGet, ID: 1}, Peer{UID: 501})
	if resp.Error == nil || resp.Error.Code != ErrCodeUnauthorized {
		t.Errorf("telemetry.get for a denied peer: %+v", resp)
	}
	if strings.Contains(encode(t, resp), "abc123") {
		t.Error("a denied telemetry.get leaked the DSN")
	}
}

func TestTelemetrySetIsAPartialUpdate(t *testing.T) {
	m := &MockDaemon{telemetry: TelemetrySettings{DSN: testDSN, Errors: true, Logs: true, TracesSampleRate: 0.2}}
	h := NewHandler(m, allowAll{})
	off := false
	rate := 0.5
	resp := h.Handle(request(t, MethodTelemetrySet, SetTelemetryParams{Logs: &off, TracesSampleRate: &rate}), Peer{UID: 501, Verified: true})
	if resp.Error != nil {
		t.Fatalf("telemetry.set: %+v", resp.Error)
	}
	var got TelemetrySettings
	raw, _ := json.Marshal(resp.Result)
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	want := TelemetrySettings{DSN: testDSN, Errors: true, Logs: false, TracesSampleRate: 0.5}
	if got != want {
		t.Errorf("settings = %+v, want %+v", got, want)
	}
}

func TestTelemetrySetRejectsBadInput(t *testing.T) {
	bad := "not a dsn"
	over := 1.5
	cases := map[string]*Request{
		"no field":    request(t, MethodTelemetrySet, SetTelemetryParams{}),
		"bad dsn":     request(t, MethodTelemetrySet, SetTelemetryParams{DSN: &bad}),
		"bad rate":    request(t, MethodTelemetrySet, SetTelemetryParams{TracesSampleRate: &over}),
		"wrong types": {JSONRPC: "2.0", Method: MethodTelemetrySet, Params: json.RawMessage(`{"errors":"yes"}`), ID: 1},
	}
	for name, req := range cases {
		m := &MockDaemon{telemetry: TelemetrySettings{DSN: testDSN}}
		resp := NewHandler(m, allowAll{}).Handle(req, Peer{UID: 501, Verified: true})
		if resp.Error == nil || resp.Error.Code != ErrCodeInvalidPar {
			t.Errorf("%s: %+v", name, resp)
		}
		if m.telemetry.DSN != testDSN {
			t.Errorf("%s changed the stored DSN", name)
		}
		if strings.Contains(encode(t, resp), bad) {
			t.Errorf("%s echoed the rejected DSN", name)
		}
	}
}

func TestTelemetrySetRefusesADeniedPeer(t *testing.T) {
	m := &MockDaemon{}
	on := true
	resp := NewHandler(m, denyAll{}).Handle(request(t, MethodTelemetrySet, SetTelemetryParams{Errors: &on}), Peer{UID: 501})
	if resp.Error == nil || resp.Error.Code != ErrCodeUnauthorized || m.telemetry.Errors {
		t.Errorf("%+v, errors=%v", resp, m.telemetry.Errors)
	}
}

func TestSettingsGetNeverCarriesTheDSN(t *testing.T) {
	m := &MockDaemon{telemetry: TelemetrySettings{DSN: testDSN}}
	got := encode(t, NewHandler(m, allowAll{}).Handle(&Request{JSONRPC: "2.0", Method: MethodSettingsGet, ID: 1}, Peer{}))
	if strings.Contains(got, "abc123") || strings.Contains(strings.ToLower(got), "dsn") {
		t.Errorf("settings.get = %s", got)
	}
}
