// Package api provides JSON-RPC 2.0 types and handlers for socket communication.
package api

import (
	"encoding/json"

	"github.com/quocln/routewise/internal/activity"
	"github.com/quocln/routewise/internal/config"
	"github.com/quocln/routewise/internal/history"
)

// Request is a JSON-RPC 2.0 request.
type Request struct {
	JSONRPC string          `json:"jsonrpc"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
	ID      interface{}     `json:"id"`

	// peer is who sent the request. Handle sets it from the kernel's socket
	// credentials; it is unexported and has no JSON name, so a request body can
	// never supply or override it.
	peer Peer
}

// Response is a JSON-RPC 2.0 response.
type Response struct {
	JSONRPC string      `json:"jsonrpc"`
	Result  interface{} `json:"result,omitempty"`
	Error   *Error      `json:"error,omitempty"`
	ID      interface{} `json:"id"`
}

// Error represents a JSON-RPC 2.0 error.
type Error struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// StatusResult is the response for status.get.
//
// Optional fields are omitted when empty, so a client must treat an absent
// field as its zero value. VPNConnected means at least one full-tunnel VPN
// (AWS Client VPN, OpenVPN, or WireGuard) that RouteWise has detected and
// manages. Several can be managed at once: Tunnels lists each of them in
// priority order, and VPNInterface and VPNClient describe the first one, the
// highest-priority connected tunnel.
type StatusResult struct {
	Running      bool   `json:"running"`
	VPNConnected bool   `json:"vpnConnected"`
	VPNInterface string `json:"vpnInterface,omitempty"`
	// RouteCount is the total number of routes across every managed tunnel.
	RouteCount int `json:"routeCount"`

	// Tunnels lists every managed tunnel, highest priority first.
	Tunnels []TunnelStatus `json:"tunnels,omitempty"`

	// DefaultVPN is the default VPN and who carries its traffic now. It is
	// absent while no default VPN is set.
	DefaultVPN *DefaultVPNStatus `json:"defaultVpn,omitempty"`

	// Degraded means route compensation could not be verified. All mutators are
	// stopped and the operator must recover before RouteWise resumes.
	Degraded bool `json:"degraded,omitempty"`

	// DegradedReason explains a degraded state in operator-facing terms.
	DegradedReason string `json:"degradedReason,omitempty"`

	// DomainCount is how many patterns are configured, across the Any VPN list
	// and every VPN's own list.
	DomainCount int `json:"domainCount,omitempty"`

	// WildcardDomains lists the domains whose lookups currently go through
	// RouteWise's DNS forwarder so wildcard patterns under them get routed.
	// Empty while the VPN is down or no wildcard pattern is configured.
	WildcardDomains []string `json:"wildcardDomains,omitempty"`

	// WildcardError explains why wildcard routing is not active although
	// wildcard patterns are configured (for example, the forwarder's port is
	// taken, or a resolver file RouteWise does not own already exists).
	WildcardError string `json:"wildcardError,omitempty"`

	// VPNDNSServers lists the VPN's DNS servers, which RouteWise routes into
	// the tunnel. UseVPNDNS reports whether it also resolves through them
	// (dns.use_vpn_dns).
	VPNDNSServers []string `json:"vpnDnsServers,omitempty"`
	UseVPNDNS     bool     `json:"useVpnDns,omitempty"`

	// CaptureDropped counts packets the kernel discarded because a capture
	// buffer was full. A rising count means the activity log and the access
	// history are incomplete. Absent while none was dropped.
	CaptureDropped uint64 `json:"captureDropped,omitempty"`

	// VPNClient is the program that owns the managed tunnel.
	VPNClient *VPNClient `json:"vpnClient,omitempty"`
	// PendingVPN is a full-tunnel VPN RouteWise detected but leaves alone,
	// because its client is not on the allowlist. With several, it is the
	// first of PendingVPNs, kept for clients that read only one.
	PendingVPN *PendingVPN `json:"pendingVpn,omitempty"`
	// PendingVPNs lists every such VPN, ordered by interface.
	PendingVPNs []PendingVPN `json:"pendingVpns,omitempty"`
}

// TunnelStatus is one managed VPN tunnel.
type TunnelStatus struct {
	Interface string `json:"interface"`
	// Client is the program that owns the tunnel; its ID is empty when the
	// owner could not be identified.
	Client VPNClient `json:"client"`
	// RouteCount is the number of routes RouteWise holds through this tunnel.
	RouteCount int `json:"routeCount"`
	// VPNDNSServers are the tunnel's DNS servers, which RouteWise routes into
	// it.
	VPNDNSServers []string `json:"vpnDnsServers,omitempty"`
	// ProfileID names the built-in profile behind the tunnel; empty for a
	// tunnel another program owns.
	ProfileID string `json:"profileId,omitempty"`
}

// ImportConfigParams is the request body of config.import.
type ImportConfigParams struct {
	Config config.Export `json:"config"`
}

// ImportConfigResult is the response of config.import.
type ImportConfigResult struct {
	// RestartRequired is true when DNS servers, cache TTL, or routing mode
	// changed: the helper reads those at start.
	RestartRequired bool `json:"restartRequired"`
}

// ActivityParams is the request body of activity.list.
type ActivityParams struct {
	// Since returns only events newer than this sequence number; 0 returns
	// everything kept.
	Since uint64 `json:"since,omitempty"`
	// Limit caps how many of the newest events are returned; 0 means all.
	Limit int `json:"limit,omitempty"`
	// WaitMs, when set, holds the request until an event newer than Since
	// exists or this many milliseconds pass (at most 20000), so a client
	// sees activity the moment it happens instead of on its next poll.
	WaitMs int `json:"waitMs,omitempty"`
}

// ActivityResult is the response of activity.list.
type ActivityResult struct {
	// Latest is the newest sequence number; pass it as Since next time.
	Latest uint64           `json:"latest"`
	Events []activity.Event `json:"events"`
}

// AccessListParams is the request body of access.list.
type AccessListParams = history.Query

// AccessListResult is the response of access.list.
type AccessListResult = history.Result

// PrefsResult is the response of prefs.get: the calling user's app
// preferences, each value as the JSON it was stored with.
type PrefsResult struct {
	Prefs map[string]json.RawMessage `json:"prefs"`
}

// PrefsSetParams is the request body of prefs.set. The preferences belong to
// the calling peer's uid, never to a uid named in the request.
type PrefsSetParams struct {
	// Key matches ^[A-Za-z][A-Za-z0-9._-]{0,63}$.
	Key string `json:"key"`
	// Value is any JSON of at most 4096 bytes; null deletes the key. An absent
	// value is rejected, so a typo cannot delete a preference.
	Value json.RawMessage `json:"value"`
}

// AccessClearResult is the response of access.clear.
type AccessClearResult struct {
	// Deleted is how many access records were removed.
	Deleted int64 `json:"deleted"`
}

// DNSCleanResult is the response of dns.clean.
type DNSCleanResult struct {
	// RoutesRemoved is how many learned wildcard routes were removed.
	RoutesRemoved int `json:"routesRemoved"`
}

// CheckHostParams is the request body of routes.check.
type CheckHostParams struct {
	// Host is a hostname, an IP address, or a URL.
	Host string `json:"host"`
}

// HostCheck says where traffic to a host goes right now.
type HostCheck struct {
	Host string `json:"host"`
	// MatchedPatterns are the configured domain patterns the host matches.
	MatchedPatterns []string `json:"matchedPatterns,omitempty"`
	// VPNInterface is the highest-priority managed tunnel, empty when no VPN
	// is managed. An address can leave through any managed tunnel; its own
	// Interface and VPN say which.
	VPNInterface string        `json:"vpnInterface,omitempty"`
	Addresses    []HostAddress `json:"addresses"`
}

// HostAddress is one address of a checked host and the kernel's route to it.
type HostAddress struct {
	IP string `json:"ip"`
	// Verdict is "vpn" or "direct".
	Verdict   string `json:"verdict"`
	Interface string `json:"interface,omitempty"`
	// VPN names the client of the managed tunnel the address leaves through;
	// empty for a direct address.
	VPN     string `json:"vpn,omitempty"`
	Gateway string `json:"gateway,omitempty"`
	// RoutedFor is the domain RouteWise added the address's route for.
	RoutedFor string `json:"routedFor,omitempty"`
	Note      string `json:"note,omitempty"`
}

// VPNClient identifies the program that owns a VPN tunnel.
type VPNClient struct {
	// ID is the client's executable path, the key the allowlist uses.
	ID string `json:"id"`
	// Name is the app or binary name to show the user.
	Name string `json:"name"`
}

// PendingVPN is a detected tunnel waiting for the user to allow its client.
type PendingVPN struct {
	Interface string    `json:"interface"`
	Client    VPNClient `json:"client"`
}

// SetVPNClientParams is the request body of vpn.setAllowed.
type SetVPNClientParams struct {
	ClientID string `json:"clientId"`
	Allowed  bool   `json:"allowed"`
}

// VPNScanResult is the result of vpn.scan: the VPN clients installed on this
// machine that are not allowed yet. Each is a candidate; only connecting shows
// whether it creates a full tunnel.
type VPNScanResult struct {
	Clients []VPNClient `json:"clients"`
}

// VPNResolveParams is the request body of vpn.resolve.
type VPNResolveParams struct {
	// Path is the app or program the user chose.
	Path string `json:"path"`
}

// Peer identifies the process on the other end of the control socket, as
// reported by the kernel rather than by the client itself.
//
// Verified is false when the credentials could not be read at all. Such a
// connection is treated as read-only: socket group membership grants status,
// never the ability to change routing.
//
// On Unix the identity is the UID. A Windows peer has no UID: it carries the
// token's user SID, its session id and whether it is an enabled administrator,
// and is recognised by a non-empty SID (a UID of 0 means root only on Unix).
type Peer struct {
	UID      uint32
	Verified bool

	SID     string
	Session uint32
	Admin   bool
}

// Domain represents a domain routing rule.
type Domain struct {
	Pattern string `json:"pattern"`
}

// AddDomainParams is the params for domains.add.
type AddDomainParams struct {
	Pattern string `json:"pattern"`
	// VPN is the VPN client whose list the pattern joins; empty is Any VPN.
	VPN string `json:"vpn,omitempty"`
}

// ListDomainsParams is the optional params of domains.list.
type ListDomainsParams struct {
	// VPN selects a VPN client's list; empty is Any VPN.
	VPN string `json:"vpn,omitempty"`
}

// RemoveDomainParams is the params for domains.remove.
type RemoveDomainParams struct {
	Pattern string `json:"pattern"`
	VPN     string `json:"vpn,omitempty"`
}

// SetDomainsParams is the params for domains.set (bulk replace all domains).
type SetDomainsParams struct {
	Patterns []string `json:"patterns"`
	// VPN selects the list to replace: a VPN client's, or Any VPN when empty.
	VPN string `json:"vpn,omitempty"`

	// Revision, when non-zero, makes the write conditional on the client having
	// edited the current list. A client that omits it accepts last-writer-wins.
	Revision uint64 `json:"revision,omitempty"`
}

// Settings is the response for settings.get and settings.set: the settings the
// app can change while the helper runs.
type Settings struct {
	// UseVPNDNS mirrors dns.use_vpn_dns: resolve through the VPN's DNS servers.
	UseVPNDNS bool `json:"useVpnDns"`
	// AllowIPv6 mirrors routing.allow_ipv6. While it is false, the IPv6
	// addresses of listed names are blocked so apps use IPv4.
	AllowIPv6 bool `json:"allowIpv6"`
	// DefaultVPN mirrors routing.default_vpn: the client ID of the VPN that
	// carries traffic no list claims. Empty leaves it direct.
	DefaultVPN string `json:"defaultVpn"`
	// DefaultVPNFallback mirrors routing.default_vpn_fallback: the client ID of
	// the VPN that takes over while DefaultVPN is down. Empty goes direct.
	DefaultVPNFallback string `json:"defaultVpnFallback"`
	// DefaultVPNExcept mirrors routing.default_vpn_except: the domains, wildcards,
	// IPs and networks that go direct instead of through the default VPN.
	DefaultVPNExcept []string `json:"defaultVpnExcept"`
	// AllowedVPNClients are the VPN clients RouteWise may manage.
	AllowedVPNClients []VPNClient `json:"allowedVpnClients"`
	// HistoryEnabled mirrors history.enabled: record new outbound connections.
	HistoryEnabled bool `json:"historyEnabled"`
	// HistoryRetentionDays mirrors history.retention_days (1 to 90).
	HistoryRetentionDays int `json:"historyRetentionDays"`
}

// SetSettingsParams is the request body of settings.set. A field left out is
// not changed.
type SetSettingsParams struct {
	UseVPNDNS            *bool `json:"useVpnDns,omitempty"`
	AllowIPv6            *bool `json:"allowIpv6,omitempty"`
	HistoryEnabled       *bool `json:"historyEnabled,omitempty"`
	HistoryRetentionDays *int  `json:"historyRetentionDays,omitempty"`
	// DefaultVPN and DefaultVPNFallback are client IDs; empty clears one.
	// Clearing the default VPN clears its fallback too.
	DefaultVPN         *string `json:"defaultVpn,omitempty"`
	DefaultVPNFallback *string `json:"defaultVpnFallback,omitempty"`
	// DefaultVPNExcept replaces the whole list; an empty list clears it.
	DefaultVPNExcept *[]string `json:"defaultVpnExcept,omitempty"`
}

// ProfileKind names a runtime profile of the helper.
type ProfileKind string

const (
	ProfileCPU   ProfileKind = "cpu"
	ProfileHeap  ProfileKind = "heap"
	ProfileMutex ProfileKind = "mutex"
)

// MaxProfileSeconds bounds how long debug.profile may hold a request.
const MaxProfileSeconds = 300

// ProfileParams is the request body of debug.profile.
type ProfileParams struct {
	Kind    ProfileKind `json:"kind"`
	Seconds int         `json:"seconds"`
	// WaitMs tells the client how long the helper holds the answer.
	WaitMs int `json:"waitMs,omitempty"`
}

// ProfileResult is a profile in pprof format.
type ProfileResult struct {
	Data []byte `json:"data"`
}

// DefaultVPNState says who carries the traffic no list claims.
type DefaultVPNState string

const (
	// DefaultVPNPrimary means the chosen default VPN carries it.
	DefaultVPNPrimary DefaultVPNState = "primary"
	// DefaultVPNFallback means the default VPN is down and its fallback carries it.
	DefaultVPNFallback DefaultVPNState = "fallback"
	// DefaultVPNDirect means no VPN can carry it, so it goes direct.
	DefaultVPNDirect DefaultVPNState = "direct"
)

// DefaultVPNStatus is the default VPN setting and its effect right now.
type DefaultVPNStatus struct {
	// Client and Fallback are the configured client IDs.
	Client   string          `json:"client"`
	Fallback string          `json:"fallback,omitempty"`
	State    DefaultVPNState `json:"state"`
	// ActiveClient and ActiveInterface name the VPN that carries the traffic.
	ActiveClient    string `json:"activeClient,omitempty"`
	ActiveInterface string `json:"activeInterface,omitempty"`
	// Problem says why a connected VPN is not carrying the traffic.
	Problem string `json:"problem,omitempty"`
}

// TelemetrySettings is the response of telemetry.get and telemetry.set. It
// holds the DSN, so only the private methods return it; settings.get never
// does.
type TelemetrySettings struct {
	DSN              string  `json:"dsn"`
	Errors           bool    `json:"errors"`
	Sessions         bool    `json:"sessions"`
	Logs             bool    `json:"logs"`
	Traces           bool    `json:"traces"`
	TracesSampleRate float64 `json:"tracesSampleRate"`
}

// SetTelemetryParams is the request body of telemetry.set. A field left out is
// not changed.
type SetTelemetryParams struct {
	DSN              *string  `json:"dsn,omitempty"`
	Errors           *bool    `json:"errors,omitempty"`
	Sessions         *bool    `json:"sessions,omitempty"`
	Logs             *bool    `json:"logs,omitempty"`
	Traces           *bool    `json:"traces,omitempty"`
	TracesSampleRate *float64 `json:"tracesSampleRate,omitempty"`
}

// IsEmpty reports whether the request names no setting.
func (p SetTelemetryParams) IsEmpty() bool {
	return p.DSN == nil && p.Errors == nil && p.Sessions == nil && p.Logs == nil &&
		p.Traces == nil && p.TracesSampleRate == nil
}

// DNSStatus is the daemon's DNS-side state reported through status.get.
type DNSStatus struct {
	DomainCount     int
	WildcardDomains []string
	WildcardError   string
	VPNDNSServers   []string
	UseVPNDNS       bool
	CaptureDropped  uint64
}

// RouteEntry represents an active route.
type RouteEntry struct {
	IP        string `json:"ip"`
	Gateway   string `json:"gateway"`
	Interface string `json:"interface"`
	Domain    string `json:"domain"`
	AddedAt   string `json:"addedAt"`
	Protected bool   `json:"protected"`
	// VPN and ClientID name the client whose tunnel the route goes through.
	VPN      string `json:"vpn,omitempty"`
	ClientID string `json:"clientId,omitempty"`
	// List is the client id of the domain list the route was added for: ""
	// is the Any VPN list, nil is none (a VPN DNS server route).
	List *string `json:"list,omitempty"`
	// Rule is the list entry the route was added for.
	Rule string `json:"rule,omitempty"`
}

// SuccessResult is a generic success response.
type SuccessResult struct {
	Success bool `json:"success"`
}

// JSON-RPC 2.0 error codes.
const (
	ErrCodeParse      = -32700 // Invalid JSON
	ErrCodeInvalidReq = -32600 // Invalid Request
	ErrCodeMethodNF   = -32601 // Method not found
	ErrCodeInvalidPar = -32602 // Invalid params
	ErrCodeInternal   = -32603 // Internal error
	ErrCodeServer     = -32000 // Server error (custom)

	// ErrCodeUnauthorized rejects a mutation from a peer that may read status but
	// may not change routing.
	ErrCodeUnauthorized = -32001
)

// Built-in VPN profile states.
const (
	ProfileDisconnected     = "disconnected"
	ProfileConnecting       = "connecting"
	ProfileConnected        = "connected"
	ProfileError            = "error"
	ProfileNeedsCredentials = "needsCredentials"
)

// ProfileStats is the live traffic view of a connected profile. LastHandshakeMs
// is the epoch time of the last WireGuard handshake in milliseconds, absent when
// there has been none (and always for Outline). Flow counts are Outline only.
type ProfileStats struct {
	RxBytes         uint64 `json:"rxBytes"`
	TxBytes         uint64 `json:"txBytes"`
	LastHandshakeMs *int64 `json:"lastHandshakeMs,omitempty"`
	TCPFlows        *int   `json:"tcpFlows,omitempty"`
	UDPFlows        *int   `json:"udpFlows,omitempty"`
}

// ProfileInfo is one entry of profiles.list. It never carries a secret.
type ProfileInfo struct {
	ID          string   `json:"id"`
	Kind        string   `json:"kind"`
	Name        string   `json:"name"`
	AutoConnect bool     `json:"autoConnect"`
	DNS         []string `json:"dns"`
	State       string   `json:"state"`
	Interface   string   `json:"interface,omitempty"`
	Error       string   `json:"error,omitempty"`
	// Server is host:port only.
	Server string        `json:"server,omitempty"`
	Stats  *ProfileStats `json:"stats,omitempty"`
}

// ProfileImportParams is the request body of profiles.import. Exactly one of
// WireguardConfig (kind "wireguard") or AccessKey (kind "outline", or "socks5" or
// "http" as a URL of that scheme) carries the
// secret, which is validated by parsing and never echoed.
type ProfileImportParams struct {
	Kind            string `json:"kind"`
	Name            string `json:"name"`
	WireguardConfig string `json:"wireguardConfig,omitempty"`
	AccessKey       string `json:"accessKey,omitempty"`
	AutoConnect     bool   `json:"autoConnect,omitempty"`
}

// ProfileImportResult is the response of profiles.import.
type ProfileImportResult struct {
	ID string `json:"id"`
}

// ProfileUpdateParams is the request body of profiles.update. A field left out
// is not changed; a new secret replaces the stored one.
type ProfileUpdateParams struct {
	ID              string    `json:"id"`
	Name            *string   `json:"name,omitempty"`
	AutoConnect     *bool     `json:"autoConnect,omitempty"`
	DNS             *[]string `json:"dns,omitempty"`
	WireguardConfig string    `json:"wireguardConfig,omitempty"`
	AccessKey       string    `json:"accessKey,omitempty"`
}

// ProfileIDParams is the request body of profiles.remove, profiles.connect and
// profiles.disconnect.
type ProfileIDParams struct {
	ID string `json:"id"`
}
