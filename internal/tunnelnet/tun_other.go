//go:build !darwin && !linux && !windows

package tunnelnet

import (
	"context"

	"golang.zx2c4.com/wireguard/tun"

	"github.com/quocln/routewise/internal/platform"
)

// CreateTUN reports that creating a TUN device is not implemented for this OS.
func CreateTUN(int) (tun.Device, error) { return nil, platform.Unsupported("TUN device creation") }

// AddAlias reports that configuring a tunnel's address is not implemented for
// this OS.
func AddAlias(context.Context, CommandRunner, string, string, string) error {
	return platform.Unsupported("tunnel address configuration")
}

// Up reports that bringing a tunnel interface up is not implemented for this OS.
func Up(context.Context, CommandRunner, string) error {
	return platform.Unsupported("tunnel interface configuration")
}
