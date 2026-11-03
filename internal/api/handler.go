package api

import (
	"encoding/json"
	"errors"
	"slices"
	"sort"
	"time"

	"github.com/quocln/routewise/internal/activity"
	"github.com/quocln/routewise/internal/config"
	"github.com/quocln/routewise/internal/history"
)

// MaxDomainPatterns is the maximum number of domain patterns allowed.
const MaxDomainPatterns = config.MaxDomainPatterns

// ErrRejected marks a mutation failure caused by the request itself — an unknown
// or duplicate pattern, an out-of-range list, or a stale revision. The daemon wraps such failures with it so the handler
// can answer "invalid params" instead of reporting a server fault.
var ErrRejected = errors.New("request rejected")

// ErrUnauthorized marks a peer that may read status but may not change routing.
var ErrUnauthorized = errors.New("not authorized to change routing")

// DaemonStatus is the daemon-owned surface the RPC handler is allowed to touch.
// The handler holds no configuration of its own: every read and every mutation
// goes through the daemon so that the config file has exactly one writer.
// StatusReader is what status.get and routes.list read.
type StatusReader interface {
	IsRunning() bool
	GetVPNConnected() bool
	GetVPNInterface() string
	GetRouteCount() int
	GetActiveRoutes() []RouteEntry
	Degraded() (bool, string)
	DNSStatus() DNSStatus
	DefaultVPNStatus() *DefaultVPNStatus
	// VPNClients reports the client of the highest-priority managed tunnel and
	// a detected tunnel RouteWise leaves alone.
	VPNClients() (managed *VPNClient, pending []PendingVPN)
	// Tunnels lists every managed tunnel, highest priority first.
	Tunnels() []TunnelStatus
	CheckHost(host string) (HostCheck, error)
}

// SettingsController changes the settings that take effect while the helper runs.
type SettingsController interface {
	Settings() Settings
	SetUseVPNDNS(enabled bool) error
	SetAllowIPv6(allowed bool) error
	// SetDefaultVPN changes the default VPN and its fallback; a nil argument is
	// left as it is. A client that is not allowed is reported as ErrRejected.
	SetDefaultVPN(client, fallback *string) error
	// SetHistory changes history.enabled and history.retention_days; a nil
	// argument is left as it is. A retention change purges at once.
	SetHistory(enabled *bool, retentionDays *int) error
	SetVPNClientAllowed(id string, allowed bool) error
	// ScanVPNClients lists the VPN clients installed here that are not allowed yet.
	ScanVPNClients() []VPNClient
	// ResolveVPNClient returns the client a chosen program stands for. A program
	// that could never own a tunnel is reported as ErrRejected.
	ResolveVPNClient(path string) (VPNClient, error)
	// Telemetry returns the error-reporting settings, DSN included.
	Telemetry() TelemetrySettings
	// SetTelemetry applies the settings named in p; a nil field is left as it
	// is. An invalid value is reported as ErrRejected.
	SetTelemetry(p SetTelemetryParams) error
}

// DNSMaintainer empties what the helper and the system have remembered.
type DNSMaintainer interface {
	// ClearDNSCache empties RouteWise's DNS cache and the system's. No route
	// changes.
	ClearDNSCache() error
	// CleanDNS removes the routes learned from wildcard lookups, then does what
	// ClearDNSCache does, and returns how many routes it removed. Connections
	// open over those routes can drop until the next lookup routes them again.
	CleanDNS() (routesRemoved int, err error)
}

// ProfileController manages the built-in VPN profiles. None of these returns or logs
// a secret.
type ProfileController interface {
	ProfilesList() []ProfileInfo
	ProfileImport(p ProfileImportParams) (id string, err error)
	ProfileUpdate(p ProfileUpdateParams) error
	ProfileRemove(id string) error
	ProfileConnect(id string) error
	ProfileDisconnect(id string) error
}

// HistoryReader answers what happened: the activity log and the access history.
type HistoryReader interface {
	Activity(since uint64, limit int, wait time.Duration) (latest uint64, events []activity.Event)
	// AccessList answers an access history query, holding a long-poll query
	// up to its wait. An invalid query is reported as ErrRejected.
	AccessList(q AccessListParams) (AccessListResult, error)
	// AccessClear deletes the whole access history and returns how many
	// records it held.
	AccessClear() (deleted int64, err error)
}

// PrefsStore keeps the app's preferences per user.
type PrefsStore interface {
	// Prefs returns the app preferences stored for uid. SetPref stores one
	// value (any JSON) under key for uid, or deletes the key when value is
	// JSON null; a malformed key or value, or a user over the key limit, is
	// reported as ErrRejected.
	Prefs(uid uint32) (map[string]json.RawMessage, error)
	SetPref(uid uint32, key string, value json.RawMessage) error
}

// DomainEditor edits the domain lists and moves the whole configuration in and out.
type DomainEditor interface {
	// Domain lists are per VPN client; vpn "" is the Any VPN list.
	ListDomains(vpn string) (patterns []string, revision uint64, err error)
	AddDomain(vpn, pattern string) error
	RemoveDomain(vpn, pattern string) error
	SetDomains(vpn string, patterns []string, expectedRevision uint64) error
	// TriggerSync asks for a route sync after an edit.
	TriggerSync()
	ExportConfig() config.Export
	ImportConfig(e config.Export) (restartRequired bool, err error)
}

// Profiler records runtime profiles of the helper.
type Profiler interface {
	// Profile records a runtime profile of the helper. An invalid request is
	// reported as ErrRejected.
	Profile(kind ProfileKind, seconds int) ([]byte, error)
}

// DaemonStatus is everything the RPC handler asks of the daemon, one interface per
// area, so a new area is a new interface and a test double can see what it stands in for.
type DaemonStatus interface {
	StatusReader
	SettingsController
	DNSMaintainer
	ProfileController
	HistoryReader
	PrefsStore
	DomainEditor
	Profiler
}

// MutationAuthorizer decides whether a peer may change routing state. Reads are
// governed by socket permissions alone; writes additionally require this check,
// so a process that merely holds the socket's group cannot reroute traffic.
type MutationAuthorizer interface {
	AllowMutation(peer Peer) error
}

// Handler handles JSON-RPC requests.
type Handler struct {
	daemon     DaemonStatus
	authorizer MutationAuthorizer
}

// NewHandler creates a new RPC handler. A nil authorizer denies every mutation,
// so a wiring mistake fails closed instead of opening the socket up.
func NewHandler(daemon DaemonStatus, authorizer MutationAuthorizer) *Handler {
	return &Handler{daemon: daemon, authorizer: authorizer}
}

// Handle processes a JSON-RPC request and returns a response. The peer comes
// from the kernel, never from the request body, so a client cannot claim an
// identity it does not have.
func (h *Handler) Handle(req *Request, peer Peer) *Response {
	if req.JSONRPC != "2.0" {
		return errorResponse(req.ID, ErrCodeInvalidReq, "Invalid JSON-RPC version")
	}

	method, ok := rpcMethods[req.Method]
	if !ok {
		return errorResponse(req.ID, ErrCodeMethodNF, "Method not found")
	}
	// Work on a copy so the caller's request is not changed.
	tagged := *req
	tagged.peer = peer
	req = &tagged
	if method.auth == AuthPublic {
		return method.handle(h, req)
	}
	return h.authorized(req, peer, func(r *Request) *Response { return method.handle(h, r) })
}

// authorized runs a mutating method only for a peer allowed to change routing.
func (h *Handler) authorized(req *Request, peer Peer, fn func(*Request) *Response) *Response {
	if h.authorizer == nil {
		return errorResponse(req.ID, ErrCodeUnauthorized, ErrUnauthorized.Error())
	}
	if err := h.authorizer.AllowMutation(peer); err != nil {
		return errorResponse(req.ID, ErrCodeUnauthorized, err.Error())
	}
	return fn(req)
}

// getStatus returns the daemon status.
func (h *Handler) getStatus(req *Request) *Response {
	degraded, reason := h.daemon.Degraded()
	dnsStatus := h.daemon.DNSStatus()
	result := StatusResult{
		Running:         h.daemon.IsRunning(),
		VPNConnected:    h.daemon.GetVPNConnected(),
		VPNInterface:    h.daemon.GetVPNInterface(),
		RouteCount:      h.daemon.GetRouteCount(),
		Degraded:        degraded,
		DegradedReason:  reason,
		DomainCount:     dnsStatus.DomainCount,
		WildcardDomains: dnsStatus.WildcardDomains,
		WildcardError:   dnsStatus.WildcardError,
		VPNDNSServers:   dnsStatus.VPNDNSServers,
		UseVPNDNS:       dnsStatus.UseVPNDNS,
		CaptureDropped:  dnsStatus.CaptureDropped,
	}
	var pending []PendingVPN
	result.VPNClient, pending = h.daemon.VPNClients()
	if len(pending) > 0 {
		result.PendingVPN = &pending[0]
		result.PendingVPNs = pending
	}
	result.Tunnels = h.daemon.Tunnels()
	result.DefaultVPN = h.daemon.DefaultVPNStatus()
	return successResponse(req.ID, result)
}

// listDomains returns configured domain patterns.
func (h *Handler) listDomains(req *Request) *Response {
	params, err := decodeParams[ListDomainsParams](req, true)
	if err != nil {
		return errorResponse(req.ID, ErrCodeInvalidPar, "Invalid params")
	}
	patterns, _, err := h.daemon.ListDomains(params.VPN)
	if err != nil {
		return errorResponse(req.ID, ErrCodeInvalidPar, err.Error())
	}
	domains := make([]Domain, 0, len(patterns))
	for _, p := range patterns {
		domains = append(domains, Domain{Pattern: p})
	}
	// Sort alphabetically
	sort.Slice(domains, func(i, j int) bool {
		return domains[i].Pattern < domains[j].Pattern
	})
	return successResponse(req.ID, domains)
}

// addDomain adds a new domain pattern.
func (h *Handler) addDomain(req *Request) *Response {
	params, err := decodeParams[AddDomainParams](req, false)
	if err != nil {
		return errorResponse(req.ID, ErrCodeInvalidPar, "Invalid params")
	}

	if params.Pattern == "" {
		return errorResponse(req.ID, ErrCodeInvalidPar, "Pattern cannot be empty")
	}

	if _, err := config.ParseEntry(params.Pattern); err != nil {
		return errorResponse(req.ID, ErrCodeInvalidPar, invalidEntryMessage(params.Pattern, err))
	}

	if err := h.daemon.AddDomain(params.VPN, params.Pattern); err != nil {
		return mutationErrorResponse(req.ID, err)
	}

	// Trigger route sync
	h.daemon.TriggerSync()

	return successResponse(req.ID, SuccessResult{Success: true})
}

// removeDomain removes a domain pattern.
func (h *Handler) removeDomain(req *Request) *Response {
	params, err := decodeParams[RemoveDomainParams](req, false)
	if err != nil {
		return errorResponse(req.ID, ErrCodeInvalidPar, "Invalid params")
	}

	if params.Pattern == "" {
		return errorResponse(req.ID, ErrCodeInvalidPar, "Pattern cannot be empty")
	}

	if err := h.daemon.RemoveDomain(params.VPN, params.Pattern); err != nil {
		return mutationErrorResponse(req.ID, err)
	}

	// Trigger route sync
	h.daemon.TriggerSync()

	return successResponse(req.ID, SuccessResult{Success: true})
}

// setDomains replaces all domain patterns (bulk update).
func (h *Handler) setDomains(req *Request) *Response {
	params, err := decodeParams[SetDomainsParams](req, false)
	if err != nil {
		return errorResponse(req.ID, ErrCodeInvalidPar, "Invalid params")
	}

	// An empty array clears the list; a missing or null one is a malformed
	// request, so a client bug cannot wipe a list by omission.
	if params.Patterns == nil {
		return errorResponse(req.ID, ErrCodeInvalidPar, "Invalid params: patterns is required")
	}

	// Validate all patterns
	accepted := make([]string, 0, len(params.Patterns))
	for _, pattern := range params.Patterns {
		if pattern == "" {
			continue // Skip empty lines
		}
		if _, err := config.ParseEntry(pattern); err != nil {
			return errorResponse(req.ID, ErrCodeInvalidPar, invalidEntryMessage(pattern, err))
		}
		accepted = append(accepted, pattern)
	}

	// Check domain count limit
	if len(accepted) > MaxDomainPatterns {
		return errorResponse(req.ID, ErrCodeInvalidPar, "Maximum domain limit exceeded")
	}

	if err := h.daemon.SetDomains(params.VPN, accepted, params.Revision); err != nil {
		return mutationErrorResponse(req.ID, err)
	}

	// Trigger route sync
	h.daemon.TriggerSync()

	return successResponse(req.ID, SuccessResult{Success: true})
}

// settingRule is how settings.set handles one setting or group of settings.
type settingRule struct {
	given func(p *SetSettingsParams) bool
	// validate, when set, runs for every given setting before any is applied, so a
	// bad value cannot leave the request half done.
	validate func(p *SetSettingsParams) error
	apply    func(d DaemonStatus, p *SetSettingsParams) error
}

// settingRules lists what settings.set can change. The default VPN comes first: the
// daemon alone can tell whether its values are acceptable, so nothing is applied yet
// if it refuses them.
var settingRules = []settingRule{
	{
		given: func(p *SetSettingsParams) bool { return p.DefaultVPN != nil || p.DefaultVPNFallback != nil },
		apply: func(d DaemonStatus, p *SetSettingsParams) error {
			return d.SetDefaultVPN(p.DefaultVPN, p.DefaultVPNFallback)
		},
	},
	{
		given: func(p *SetSettingsParams) bool { return p.UseVPNDNS != nil },
		apply: func(d DaemonStatus, p *SetSettingsParams) error { return d.SetUseVPNDNS(*p.UseVPNDNS) },
	},
	{
		given: func(p *SetSettingsParams) bool { return p.AllowIPv6 != nil },
		apply: func(d DaemonStatus, p *SetSettingsParams) error { return d.SetAllowIPv6(*p.AllowIPv6) },
	},
	{
		given: func(p *SetSettingsParams) bool { return p.HistoryEnabled != nil || p.HistoryRetentionDays != nil },
		validate: func(p *SetSettingsParams) error {
			if p.HistoryRetentionDays == nil {
				return nil
			}
			return config.ValidateHistoryRetention(*p.HistoryRetentionDays)
		},
		apply: func(d DaemonStatus, p *SetSettingsParams) error {
			return d.SetHistory(p.HistoryEnabled, p.HistoryRetentionDays)
		},
	},
}

// setSettings changes the runtime settings named in the request and returns
// the settings now in effect.
func (h *Handler) setSettings(req *Request) *Response {
	params, err := decodeParams[SetSettingsParams](req, false)
	if err != nil {
		return errorResponse(req.ID, ErrCodeInvalidPar, "Invalid params")
	}
	var given []settingRule
	for _, rule := range settingRules {
		if !rule.given(&params) {
			continue
		}
		if rule.validate != nil {
			if err := rule.validate(&params); err != nil {
				return errorResponse(req.ID, ErrCodeInvalidPar, err.Error())
			}
		}
		given = append(given, rule)
	}
	if len(given) == 0 {
		return errorResponse(req.ID, ErrCodeInvalidPar, "No setting to change")
	}
	for _, rule := range given {
		if err := rule.apply(h.daemon, &params); err != nil {
			return mutationErrorResponse(req.ID, err)
		}
	}
	return successResponse(req.ID, h.daemon.Settings())
}

// debugProfile records a runtime profile. The connection waits for it, like a long poll.
func (h *Handler) debugProfile(req *Request) *Response {
	params, err := decodeParams[ProfileParams](req, false)
	if err != nil {
		return errorResponse(req.ID, ErrCodeInvalidPar, "Invalid params")
	}
	data, err := h.daemon.Profile(params.Kind, params.Seconds)
	if err != nil {
		return mutationErrorResponse(req.ID, err)
	}
	return successResponse(req.ID, ProfileResult{Data: data})
}

// clearDNSCache empties the DNS caches. It takes no params.
func (h *Handler) clearDNSCache(req *Request) *Response {
	if err := h.daemon.ClearDNSCache(); err != nil {
		return mutationErrorResponse(req.ID, err)
	}
	return successResponse(req.ID, SuccessResult{Success: true})
}

// cleanDNS removes the learned wildcard routes and empties the DNS caches. It
// takes no params.
func (h *Handler) cleanDNS(req *Request) *Response {
	removed, err := h.daemon.CleanDNS()
	if err != nil {
		return mutationErrorResponse(req.ID, err)
	}
	return successResponse(req.ID, DNSCleanResult{RoutesRemoved: removed})
}

// setTelemetry changes the error-reporting settings named in the request and
// returns the settings now in effect. Nothing here echoes the DSN into an error.
func (h *Handler) setTelemetry(req *Request) *Response {
	params, err := decodeParams[SetTelemetryParams](req, false)
	if err != nil {
		return errorResponse(req.ID, ErrCodeInvalidPar, "Invalid params")
	}
	if params.IsEmpty() {
		return errorResponse(req.ID, ErrCodeInvalidPar, "No setting to change")
	}
	if err := h.daemon.SetTelemetry(params); err != nil {
		return mutationErrorResponse(req.ID, err)
	}
	return successResponse(req.ID, h.daemon.Telemetry())
}

// setVPNClientAllowed adds a VPN client to the allowlist or removes it.
func (h *Handler) setVPNClientAllowed(req *Request) *Response {
	params, err := decodeParams[SetVPNClientParams](req, false)
	if err != nil || params.ClientID == "" {
		return errorResponse(req.ID, ErrCodeInvalidPar, "Invalid params: clientId is required")
	}
	if err := h.daemon.SetVPNClientAllowed(params.ClientID, params.Allowed); err != nil {
		return mutationErrorResponse(req.ID, err)
	}
	return successResponse(req.ID, h.daemon.Settings())
}

func (h *Handler) resolveVPNClient(req *Request) *Response {
	params, err := decodeParams[VPNResolveParams](req, false)
	if err != nil || params.Path == "" {
		return errorResponse(req.ID, ErrCodeInvalidPar, "Invalid params: path required")
	}
	client, err := h.daemon.ResolveVPNClient(params.Path)
	if err != nil {
		return mutationErrorResponse(req.ID, err)
	}
	return successResponse(req.ID, client)
}

// maxActivityWait bounds a long-poll so it always answers well inside the
// socket's 30 s read deadline.
const maxActivityWait = 20 * time.Second

// listActivity returns recent routing activity newer than the given sequence.
func (h *Handler) listActivity(req *Request) *Response {
	params, err := decodeParams[ActivityParams](req, true)
	if err != nil {
		return errorResponse(req.ID, ErrCodeInvalidPar, "Invalid params")
	}
	wait := min(time.Duration(params.WaitMs)*time.Millisecond, maxActivityWait)
	latest, events := h.daemon.Activity(params.Since, params.Limit, wait)
	if events == nil {
		events = []activity.Event{}
	}
	return successResponse(req.ID, ActivityResult{Latest: latest, Events: events})
}

// listAccess returns recorded connections, optionally holding the request
// until a newer one exists.
func (h *Handler) listAccess(req *Request) *Response {
	params, err := decodeParams[AccessListParams](req, true)
	if err != nil {
		return errorResponse(req.ID, ErrCodeInvalidPar, "Invalid params")
	}
	result, err := h.daemon.AccessList(params)
	if err != nil {
		return mutationErrorResponse(req.ID, err)
	}
	if result.Entries == nil {
		result.Entries = []history.Entry{}
	}
	return successResponse(req.ID, result)
}

// clearAccess deletes the access history.
func (h *Handler) clearAccess(req *Request) *Response {
	deleted, err := h.daemon.AccessClear()
	if err != nil {
		return mutationErrorResponse(req.ID, err)
	}
	return successResponse(req.ID, AccessClearResult{Deleted: deleted})
}

// getPrefs returns the calling user's app preferences.
func (h *Handler) getPrefs(req *Request) *Response {
	prefs, err := h.daemon.Prefs(req.peer.UID)
	if err != nil {
		return mutationErrorResponse(req.ID, err)
	}
	if prefs == nil {
		prefs = map[string]json.RawMessage{}
	}
	return successResponse(req.ID, PrefsResult{Prefs: prefs})
}

// setPref stores or deletes one of the calling user's app preferences.
func (h *Handler) setPref(req *Request) *Response {
	params, err := decodeParams[PrefsSetParams](req, false)
	if err != nil || params.Key == "" || params.Value == nil {
		return errorResponse(req.ID, ErrCodeInvalidPar, "Invalid params: key and value are required")
	}
	if err := h.daemon.SetPref(req.peer.UID, params.Key, params.Value); err != nil {
		return mutationErrorResponse(req.ID, err)
	}
	return successResponse(req.ID, SuccessResult{Success: true})
}

// importConfig replaces the routing configuration with an export.
func (h *Handler) importConfig(req *Request) *Response {
	params, err := decodeParams[ImportConfigParams](req, false)
	if err != nil {
		return errorResponse(req.ID, ErrCodeInvalidPar, "Invalid params: config is required")
	}
	raw, err := json.Marshal(params.Config)
	if err != nil {
		return errorResponse(req.ID, ErrCodeInvalidPar, "Invalid params")
	}
	export, err := config.ParseExport(raw)
	if err != nil {
		return errorResponse(req.ID, ErrCodeInvalidPar, err.Error())
	}
	restart, err := h.daemon.ImportConfig(export)
	if err != nil {
		return mutationErrorResponse(req.ID, err)
	}
	return successResponse(req.ID, ImportConfigResult{RestartRequired: restart})
}

// checkHost reports whether traffic to a host goes through the VPN.
func (h *Handler) checkHost(req *Request) *Response {
	params, err := decodeParams[CheckHostParams](req, false)
	if err != nil || params.Host == "" {
		return errorResponse(req.ID, ErrCodeInvalidPar, "Invalid params: host is required")
	}
	result, err := h.daemon.CheckHost(params.Host)
	if err != nil {
		return mutationErrorResponse(req.ID, err)
	}
	return successResponse(req.ID, result)
}

// listRoutes returns active routes.
func (h *Handler) listRoutes(req *Request) *Response {
	routes := h.daemon.GetActiveRoutes()
	sortNewestFirst(routes)
	return successResponse(req.ID, routes)
}

// sortNewestFirst orders routes by added time, newest first. Each route's time
// is parsed once, not at every comparison, and routes with the same time (or an
// unparsable one) keep the order the daemon listed them in.
func sortNewestFirst(routes []RouteEntry) {
	type timed struct {
		route RouteEntry
		at    time.Time
	}
	items := make([]timed, len(routes))
	for i, r := range routes {
		at, _ := time.Parse(time.RFC3339, r.AddedAt)
		items[i] = timed{route: r, at: at}
	}
	slices.SortStableFunc(items, func(a, b timed) int { return b.at.Compare(a.at) })
	for i := range items {
		routes[i] = items[i].route
	}
}

// invalidEntryMessage explains why a list entry was rejected. A domain keeps
// the long-standing message; an IP or CIDR gets the specific reason.
func invalidEntryMessage(entry string, err error) string {
	if config.ClassifyEntry(entry) == config.EntryDomain {
		return "Invalid domain pattern: " + entry
	}
	return "Invalid entry " + entry + ": " + err.Error()
}

// successResponse creates a success response.
func successResponse(id interface{}, result interface{}) *Response {
	return &Response{
		JSONRPC: "2.0",
		Result:  result,
		ID:      id,
	}
}

// mutationErrorResponse maps a daemon mutation failure onto a JSON-RPC error.
// Rejections the caller can fix are reported as invalid params; anything else is
// a server-side failure. The daemon message is passed through because it names
// the offending pattern or revision without exposing paths or peer identity.
func mutationErrorResponse(id interface{}, err error) *Response {
	if errors.Is(err, ErrRejected) {
		return errorResponse(id, ErrCodeInvalidPar, err.Error())
	}
	return errorResponse(id, ErrCodeServer, err.Error())
}

// errorResponse creates an error response.
func errorResponse(id interface{}, code int, message string) *Response {
	return &Response{
		JSONRPC: "2.0",
		Error: &Error{
			Code:    code,
			Message: message,
		},
		ID: id,
	}
}
