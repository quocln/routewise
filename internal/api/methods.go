package api

import "encoding/json"

// JSON-RPC method names. The wire names never change; each appears once here.
const (
	MethodStatusGet   = "status.get"
	MethodSettingsGet = "settings.get"
	MethodSettingsSet = "settings.set"
	MethodRoutesList  = "routes.list"
	MethodRoutesCheck = "routes.check"

	MethodDomainsList   = "domains.list"
	MethodDomainsAdd    = "domains.add"
	MethodDomainsRemove = "domains.remove"
	MethodDomainsSet    = "domains.set"

	MethodConfigExport = "config.export"
	MethodConfigImport = "config.import"

	MethodVPNSetAllowed = "vpn.setAllowed"
	MethodVPNScan       = "vpn.scan"
	MethodVPNResolve    = "vpn.resolve"

	MethodDNSClearCache = "dns.clearCache"
	MethodDNSClean      = "dns.clean"

	MethodDebugProfile = "debug.profile"

	MethodActivityList = "activity.list"
	MethodAccessList   = "access.list"
	MethodAccessClear  = "access.clear"

	MethodPrefsGet = "prefs.get"
	MethodPrefsSet = "prefs.set"

	MethodTelemetryGet = "telemetry.get"
	MethodTelemetrySet = "telemetry.set"

	MethodProfilesList       = "profiles.list"
	MethodProfilesImport     = "profiles.import"
	MethodProfilesUpdate     = "profiles.update"
	MethodProfilesRemove     = "profiles.remove"
	MethodProfilesConnect    = "profiles.connect"
	MethodProfilesDisconnect = "profiles.disconnect"
)

// AuthLevel says who may call a method.
type AuthLevel int

const (
	// AuthPublic methods are reachable by anyone the socket permissions admit.
	AuthPublic AuthLevel = iota
	// AuthPrivateRead methods only read, but what they read is private (DNS
	// lookups, connections made, a profile's server), so they take the same
	// authorization as a change. They are not audited.
	AuthPrivateRead
	// AuthMutate methods change state: they take the authorization check and
	// every attempt is audited with the peer's identity.
	AuthMutate
)

// rpcMethod is one row of the method table: who may call it and what runs.
type rpcMethod struct {
	auth   AuthLevel
	handle func(h *Handler, req *Request) *Response
}

// profileIDMethod adapts a daemon method taking a profile id to a table handler.
func profileIDMethod(pick func(DaemonStatus) func(id string) error) func(h *Handler, req *Request) *Response {
	return func(h *Handler, req *Request) *Response {
		return h.profileByID(pick(h.daemon))(req)
	}
}

// rpcMethods is the one list of RPC methods. A method that is not here does not
// exist; its auth level is the only place that decides whether the handler
// checks authorization and whether the daemon audits the call.
var rpcMethods = map[string]rpcMethod{
	MethodStatusGet:   {AuthPublic, (*Handler).getStatus},
	MethodDomainsList: {AuthPublic, (*Handler).listDomains},
	MethodRoutesList:  {AuthPublic, (*Handler).listRoutes},
	MethodSettingsGet: {AuthPublic, func(h *Handler, req *Request) *Response {
		return successResponse(req.ID, h.daemon.Settings())
	}},
	MethodRoutesCheck: {AuthPublic, (*Handler).checkHost},
	MethodConfigExport: {AuthPublic, func(h *Handler, req *Request) *Response {
		return successResponse(req.ID, h.daemon.ExportConfig())
	}},

	// The activity log holds the DNS lookup history, which is private; a
	// profile's state carries the address of its VPN server and the error text
	// of a failed connection; the access history lists every host this Mac
	// connected to; app preferences are per user and the peer's uid picks
	// whose.
	MethodActivityList: {AuthPrivateRead, (*Handler).listActivity},
	MethodAccessList:   {AuthPrivateRead, (*Handler).listAccess},
	MethodPrefsGet:     {AuthPrivateRead, (*Handler).getPrefs},
	// The telemetry DSN is a credential for the reporting server.
	MethodTelemetryGet: {AuthPrivateRead, func(h *Handler, req *Request) *Response {
		return successResponse(req.ID, h.daemon.Telemetry())
	}},
	MethodDebugProfile: {AuthPrivateRead, (*Handler).debugProfile},
	MethodVPNScan: {AuthPrivateRead, func(h *Handler, req *Request) *Response {
		return successResponse(req.ID, VPNScanResult{Clients: h.daemon.ScanVPNClients()})
	}},
	MethodProfilesList: {AuthPrivateRead, func(h *Handler, req *Request) *Response {
		return successResponse(req.ID, h.profilesList())
	}},

	MethodConfigImport:  {AuthMutate, (*Handler).importConfig},
	MethodAccessClear:   {AuthMutate, (*Handler).clearAccess},
	MethodPrefsSet:      {AuthMutate, (*Handler).setPref},
	MethodTelemetrySet:  {AuthMutate, (*Handler).setTelemetry},
	MethodDomainsAdd:    {AuthMutate, (*Handler).addDomain},
	MethodDomainsRemove: {AuthMutate, (*Handler).removeDomain},
	MethodDomainsSet:    {AuthMutate, (*Handler).setDomains},
	MethodSettingsSet:   {AuthMutate, (*Handler).setSettings},
	MethodVPNSetAllowed: {AuthMutate, (*Handler).setVPNClientAllowed},
	// Mutate, like allowing what it returns: it has the helper look at any path.
	MethodVPNResolve:    {AuthMutate, (*Handler).resolveVPNClient},
	MethodDNSClearCache: {AuthMutate, (*Handler).clearDNSCache},
	MethodDNSClean:      {AuthMutate, (*Handler).cleanDNS},

	MethodProfilesImport:     {AuthMutate, (*Handler).profileImport},
	MethodProfilesUpdate:     {AuthMutate, (*Handler).profileUpdate},
	MethodProfilesRemove:     {AuthMutate, profileIDMethod(func(d DaemonStatus) func(string) error { return d.ProfileRemove })},
	MethodProfilesConnect:    {AuthMutate, profileIDMethod(func(d DaemonStatus) func(string) error { return d.ProfileConnect })},
	MethodProfilesDisconnect: {AuthMutate, profileIDMethod(func(d DaemonStatus) func(string) error { return d.ProfileDisconnect })},
}

// MethodAuth reports a method's auth level, and false when there is no such
// method.
func MethodAuth(method string) (AuthLevel, bool) {
	m, ok := rpcMethods[method]
	return m.auth, ok
}

// IsMutating reports whether a method changes state, which is what the daemon
// audits. An unknown method does not.
func IsMutating(method string) bool {
	m, ok := rpcMethods[method]
	return ok && m.auth == AuthMutate
}

// decodeParams unmarshals a request's params into a T. With optional set, absent
// params leave the zero value.
func decodeParams[T any](req *Request, optional bool) (T, error) {
	var params T
	if optional && len(req.Params) == 0 {
		return params, nil
	}
	err := json.Unmarshal(req.Params, &params)
	return params, err
}
