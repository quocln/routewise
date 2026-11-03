//go:build !darwin && !linux && !windows

package vpnclient

import "github.com/quocln/routewise/internal/platform"

func scanInstalled() []Client { return nil }

func resolveInstalled(string) (Client, error) {
	return Client{}, platform.Unsupported("finding installed VPN clients")
}
