//go:build !linux

package monitor

import (
	"net"

	"github.com/quocln/routewise/internal/ifacename"
)

// isInterfaceUp reports whether the named interface exists and is
// administratively up.
func isInterfaceUp(ifaceName string) bool {
	if ifacename.Validate(ifaceName) != nil {
		return false
	}

	iface, err := net.InterfaceByName(ifaceName)
	return err == nil && iface.Flags&net.FlagUp != 0
}
