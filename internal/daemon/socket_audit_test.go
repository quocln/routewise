package daemon

import (
	"log/slog"
	"strings"
	"testing"

	"github.com/quocln/routewise/internal/api"
)

// Only mutating methods are audited with the peer's identity: an accepted
// change and a denied one each leave a record, and reads, private ones
// included, leave none.
func TestAuditDoesNotCallAFailedRequestAccepted(t *testing.T) {
	var logs syncBuffer
	server := &SocketServer{logger: slog.New(slog.NewTextHandler(&logs, nil))}
	resp := &api.Response{JSONRPC: "2.0", Error: &api.Error{Code: api.ErrCodeInvalidReq, Message: "Invalid JSON-RPC version"}}
	server.auditMutation(&api.Request{Method: api.MethodDNSClean}, resp, api.Peer{UID: 501, Verified: true})
	out := logs.String()
	if !strings.Contains(out, "routing change failed") || strings.Contains(out, "accepted") {
		t.Errorf("logged %q, want a failure and no acceptance", out)
	}
}

func TestAuditRecordsMutationsAndNothingElse(t *testing.T) {
	cases := []struct {
		method  string
		denied  bool
		wantLog string
	}{
		{api.MethodDomainsAdd, false, "routing change accepted"},
		{api.MethodConfigImport, false, "routing change accepted"},
		{api.MethodAccessClear, false, "routing change accepted"},
		{api.MethodProfilesConnect, false, "routing change accepted"},
		{api.MethodDomainsSet, true, "routing change denied"},
		{api.MethodVPNSetAllowed, true, "routing change denied"},
		{api.MethodStatusGet, false, ""},
		{api.MethodActivityList, false, ""},
		{api.MethodAccessList, false, ""},
		{api.MethodProfilesList, false, ""},
		{api.MethodActivityList, true, ""},
		{"nope.nothing", false, ""},
	}
	for _, c := range cases {
		var logs syncBuffer
		server := &SocketServer{logger: slog.New(slog.NewTextHandler(&logs, nil))}
		resp := &api.Response{JSONRPC: "2.0"}
		if c.denied {
			resp.Error = &api.Error{Code: api.ErrCodeUnauthorized, Message: "denied"}
		}
		server.auditMutation(&api.Request{Method: c.method}, resp, api.Peer{UID: 501, Verified: true})
		out := logs.String()
		if c.wantLog == "" && out != "" {
			t.Errorf("%s (denied=%v) must not be audited, logged %q", c.method, c.denied, out)
		}
		if c.wantLog != "" && !strings.Contains(out, c.wantLog) {
			t.Errorf("%s (denied=%v) logged %q, want %q", c.method, c.denied, out, c.wantLog)
		}
	}
}
