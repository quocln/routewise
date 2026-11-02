package ipc

import (
	"strings"
	"testing"
)

func TestTokenIsAdmin(t *testing.T) {
	const user = "S-1-5-21-1-2-3-1001"
	for name, c := range map[string]struct {
		user   string
		groups []tokenGroup
		want   bool
	}{
		"system":                   {sidSystem, nil, true},
		"elevated administrator":   {user, []tokenGroup{{sidAdministrators, 0x7}}, true},
		"enabled, not by default":  {user, []tokenGroup{{sidAdministrators, groupEnabled}}, true},
		"filtered administrator":   {user, []tokenGroup{{sidAdministrators, groupDenyOnly | 0x1}}, false},
		"member but disabled":      {user, []tokenGroup{{sidAdministrators, 0x3}}, false},
		"standard user":            {user, []tokenGroup{{"S-1-5-32-545", 0x7}}, false},
		"no groups":                {user, nil, false},
		"another group is enabled": {user, []tokenGroup{{"S-1-5-32-551", 0x7}}, false},
	} {
		if got := tokenIsAdmin(c.user, c.groups); got != c.want {
			t.Errorf("%s: tokenIsAdmin = %v, want %v", name, got, c.want)
		}
	}
}

func TestPipeSecurityDescriptorKeepsUsersOutOfPipeCreation(t *testing.T) {
	// FILE_CREATE_PIPE_INSTANCE is FILE_APPEND_DATA (0x4): a user holding it can
	// stand up a second server instance and intercept clients.
	const createPipeInstance = 0x4
	if PipeClientAccess&createPipeInstance != 0 {
		t.Error("PipeClientAccess must not need FILE_CREATE_PIPE_INSTANCE")
	}
	const authenticatedUsersMask = 0x12018b
	if authenticatedUsersMask&createPipeInstance != 0 {
		t.Error("authenticated users must not get FILE_CREATE_PIPE_INSTANCE")
	}
	if PipeClientAccess&^(authenticatedUsersMask|0x80000000) != 0 {
		t.Errorf("PipeClientAccess %#x asks for more than the DACL grants", PipeClientAccess)
	}
	want := "(A;;0x12018b;;;AU)"
	if !strings.Contains(PipeSecurityDescriptor, want) || !strings.Contains(PipeSecurityDescriptor, "D:P") {
		t.Errorf("descriptor %q lacks %q or is not protected", PipeSecurityDescriptor, want)
	}
}

func TestPipeServerTrusted(t *testing.T) {
	admin := Peer{SID: sidSystem, Admin: true}
	user := Peer{SID: "S-1-5-21-1-2-3-1001"}
	for name, c := range map[string]struct {
		server, service uint32
		peer            Peer
		known           bool
		want            bool
	}{
		"the service's own process":          {server: 40, service: 40, want: true},
		"another process, service running":   {server: 41, service: 40, peer: user, known: true, want: false},
		"squatter whose token is unreadable": {server: 41, service: 40, want: false},
		"squatter, no service":               {server: 41, want: false},
		"foreground helper as administrator": {server: 41, peer: admin, known: true, want: true},
		"no server process":                  {server: 0, service: 0, want: false},
		"a stopped service matches nothing":  {server: 0, service: 0, peer: admin, known: true, want: false},
	} {
		if got := pipeServerTrusted(c.server, c.service, c.peer, c.known); got != c.want {
			t.Errorf("%s: pipeServerTrusted = %v, want %v", name, got, c.want)
		}
	}
}
