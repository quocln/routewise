//go:build !darwin && !linux && !windows

package vpnclient

import (
	"context"

	"github.com/quocln/routewise/internal/platform"
)

// Identify reports that finding a tunnel's owning process is not implemented
// for this OS, so no detected VPN can be admitted.
func Identify(context.Context, string) (Client, error) {
	return Client{}, platform.Unsupported("VPN client identification")
}
