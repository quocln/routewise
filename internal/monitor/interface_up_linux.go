package monitor

import (
	"net"

	"github.com/vishvananda/netlink"

	"github.com/quocln/routewise/internal/ifacename"
)

// isInterfaceUp reports whether the named link exists and is administratively
// up, read over netlink.
func isInterfaceUp(ifaceName string) bool {
	if ifacename.Validate(ifaceName) != nil {
		return false
	}
	link, err := netlink.LinkByName(ifaceName)
	return err == nil && link.Attrs().Flags&net.FlagUp != 0
}
