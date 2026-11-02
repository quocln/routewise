// Package monitor provides VPN interface monitoring for macOS.
package monitor

import (
	"net/netip"
	"time"
)

// VPNState represents the current VPN connection state.
type VPNState int

const (
	// VPNDisconnected indicates the VPN is not connected.
	VPNDisconnected VPNState = iota
	// VPNConnected indicates the VPN is connected.
	VPNConnected
)

func (s VPNState) String() string {
	switch s {
	case VPNDisconnected:
		return "disconnected"
	case VPNConnected:
		return "connected"
	default:
		return "unknown"
	}
}

// VPNEvent represents a VPN state change event.
type VPNEvent struct {
	State     VPNState
	Interface string     // Interface name, e.g., "utun3"
	Gateway   netip.Addr // VPN gateway IP
	Timestamp time.Time
}

// IsConnect returns true if this is a connect event.
func (e VPNEvent) IsConnect() bool {
	return e.State == VPNConnected
}

// IsDisconnect returns true if this is a disconnect event.
func (e VPNEvent) IsDisconnect() bool {
	return e.State == VPNDisconnected
}
