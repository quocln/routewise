package vpnclient

import (
	"context"
	"fmt"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc/mgr"

	"github.com/quocln/routewise/internal/winnet"
)

// wireGuardServicePrefix starts the name of the Windows service the official
// WireGuard client runs for each tunnel ("WireGuardTunnel$office").
const wireGuardServicePrefix = "WireGuardTunnel$"

// Identify returns the client that owns the adapter whose friendly name is
// iface (for example "Local Area Connection 3" or "office").
//
// The official WireGuard client is found by its tunnel service, whose command
// line names the executable; no process has to be inspected. Every other
// client is found among the running processes (PickWindowsClient): TAP, Wintun
// and Data Channel Offload adapters do not say which process opened them.
func Identify(ctx context.Context, iface string) (Client, error) {
	a, err := winnet.AdapterByAlias(iface)
	if err != nil {
		return Client{}, fmt.Errorf("look up %s: %w", iface, err)
	}
	if c, ok := cachedIdentity(a); ok {
		return c, nil
	}
	if kind := a.Kind(); kind == winnet.KindWireGuard || kind == winnet.KindWintun {
		if c, ok := wireGuardServiceClient(a.Alias); ok {
			rememberIdentity(a, c)
			return c, nil
		}
	}
	procs, err := runningClientProcesses(ctx)
	if err != nil {
		return Client{}, err
	}
	c, err := PickWindowsClient(a, procs)
	if err == nil {
		rememberIdentity(a, c)
	}
	return c, err
}

// wireGuardServiceClient looks up the tunnel service of the WireGuard client
// for the tunnel named alias and returns its client when the service runs the
// WireGuard executable for that very tunnel.
func wireGuardServiceClient(alias string) (Client, bool) {
	// Connect and query-config rights only: mgr.Connect asks for all access and
	// a scan that runs every few seconds should not.
	scm, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return Client{}, false
	}
	defer windows.CloseServiceHandle(scm)
	svcName, err := windows.UTF16PtrFromString(wireGuardServicePrefix + alias)
	if err != nil {
		return Client{}, false
	}
	handle, err := windows.OpenService(scm, svcName, windows.SERVICE_QUERY_CONFIG)
	if err != nil {
		return Client{}, false
	}
	s := &mgr.Service{Name: wireGuardServicePrefix + alias, Handle: handle}
	defer s.Close()
	cfg, err := s.Config()
	if err != nil {
		return Client{}, false
	}
	exe, name, ok := wireGuardTunnel(cfg.BinaryPathName)
	if !ok || name != alias {
		return Client{}, false
	}
	return FromWindowsExe(exe), true
}
