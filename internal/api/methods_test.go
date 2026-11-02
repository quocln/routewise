package api

import (
	"encoding/json"
	"sort"
	"strings"
	"testing"
)

// goldenAuth pins every method's auth level. Changing a row changes who may
// call the method and whether the daemon audits it, so it must be a decision.
var goldenAuth = map[string]AuthLevel{
	"status.get":    AuthPublic,
	"domains.list":  AuthPublic,
	"routes.list":   AuthPublic,
	"settings.get":  AuthPublic,
	"routes.check":  AuthPublic,
	"config.export": AuthPublic,

	"activity.list": AuthPrivateRead,
	"access.list":   AuthPrivateRead,
	"prefs.get":     AuthPrivateRead,
	"profiles.list": AuthPrivateRead,
	"telemetry.get": AuthPrivateRead,

	"config.import":       AuthMutate,
	"access.clear":        AuthMutate,
	"dns.clearCache":      AuthMutate,
	"dns.clean":           AuthMutate,
	"prefs.set":           AuthMutate,
	"domains.add":         AuthMutate,
	"domains.remove":      AuthMutate,
	"domains.set":         AuthMutate,
	"settings.set":        AuthMutate,
	"telemetry.set":       AuthMutate,
	"debug.profile":       AuthPrivateRead,
	"vpn.setAllowed":      AuthMutate,
	"profiles.import":     AuthMutate,
	"profiles.update":     AuthMutate,
	"profiles.remove":     AuthMutate,
	"profiles.connect":    AuthMutate,
	"profiles.disconnect": AuthMutate,
}

func TestMethodTableMatchesTheGoldenAuthLevels(t *testing.T) {
	for method, want := range goldenAuth {
		got, ok := MethodAuth(method)
		if !ok {
			t.Errorf("%s is missing from the method table", method)
			continue
		}
		if got != want {
			t.Errorf("%s auth level = %d, want %d", method, got, want)
		}
	}
	var extra []string
	for method := range rpcMethods {
		if _, ok := goldenAuth[method]; !ok {
			extra = append(extra, method)
		}
	}
	sort.Strings(extra)
	if len(extra) > 0 {
		t.Errorf("methods without a golden auth level: %v", extra)
	}
	if _, ok := MethodAuth("nope.nothing"); ok {
		t.Error("an unknown method must not be in the table")
	}
}

func TestIsMutatingIsExactlyTheMutatingMethods(t *testing.T) {
	for method, level := range goldenAuth {
		if got, want := IsMutating(method), level == AuthMutate; got != want {
			t.Errorf("IsMutating(%q) = %v, want %v", method, got, want)
		}
	}
	if IsMutating("nope.nothing") {
		t.Error("an unknown method is not mutating")
	}
}

// Only a public method answers a peer the authorizer turns down, and a handler
// built without an authorizer refuses everything else: it fails closed.
func TestEveryNonPublicMethodIsAuthorizedAndEveryPublicOneIsNot(t *testing.T) {
	denying := denyAll{}
	for method, level := range goldenAuth {
		for name, auth := range map[string]MutationAuthorizer{"denying": denying, "nil": nil} {
			h := NewHandler(&MockDaemon{running: true}, auth)
			resp := h.Handle(&Request{JSONRPC: "2.0", Method: method, ID: 1}, Peer{UID: 501})
			unauthorized := resp.Error != nil && resp.Error.Code == ErrCodeUnauthorized
			if level == AuthPublic && unauthorized {
				t.Errorf("%s (%s authorizer): a public method was refused", method, name)
			}
			if level != AuthPublic && !unauthorized {
				t.Errorf("%s (%s authorizer): a non-public method ran for an unauthorized peer: %+v", method, name, resp)
			}
		}
	}
}

func TestAnUnknownMethodIsNotFoundBeforeAnyAuthorization(t *testing.T) {
	h := NewHandler(&MockDaemon{}, denyAll{})
	resp := h.Handle(&Request{JSONRPC: "2.0", Method: "nope.nothing", ID: 1}, Peer{})
	if resp.Error == nil || resp.Error.Code != ErrCodeMethodNF {
		t.Fatalf("response = %+v, want method not found", resp)
	}
}

func TestRoutesAreListedNewestFirstAndTiesKeepDaemonOrder(t *testing.T) {
	routes := []RouteEntry{
		{IP: "1.1.1.1", AddedAt: "2026-10-28T10:00:00+07:00"},
		{IP: "2.2.2.2", AddedAt: "2026-10-28T12:00:00+07:00"},
		{IP: "3.3.3.3", AddedAt: "2026-10-28T10:00:00+07:00"},
		{IP: "4.4.4.4", AddedAt: "not a time"},
		{IP: "5.5.5.5", AddedAt: "2026-10-28T11:00:00+07:00"},
	}
	sortNewestFirst(routes)
	var got []string
	for _, r := range routes {
		got = append(got, r.IP)
	}
	want := []string{"2.2.2.2", "5.5.5.5", "1.1.1.1", "3.3.3.3", "4.4.4.4"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("order = %v, want %v", got, want)
		}
	}
}

func TestStatusReportsDroppedCapturePacketsOnlyWhenThereAreSome(t *testing.T) {
	for _, tc := range []struct {
		dropped uint64
		want    string
	}{{0, ""}, {42, `"captureDropped":42`}} {
		h := NewHandler(&MockDaemon{running: true, dnsStatus: DNSStatus{CaptureDropped: tc.dropped}}, nil)
		resp := h.Handle(&Request{JSONRPC: "2.0", Method: MethodStatusGet, ID: 1}, Peer{})
		raw, err := json.Marshal(resp)
		if err != nil {
			t.Fatal(err)
		}
		if has := strings.Contains(string(raw), "captureDropped"); has != (tc.want != "") || (tc.want != "" && !strings.Contains(string(raw), tc.want)) {
			t.Errorf("dropped %d: response %s, want %q", tc.dropped, raw, tc.want)
		}
	}
}
