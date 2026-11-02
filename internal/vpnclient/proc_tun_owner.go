package vpnclient

import (
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// tunDevicePath is what the descriptor of a tun device links to.
const tunDevicePath = "/dev/net/tun"

// tunOwnerPIDs returns, in ascending order, every process under procRoot (a
// /proc directory) that holds a tun descriptor for iface. A tun descriptor
// reports its interface in /proc/PID/fdinfo/N as the line "iff:\t<name>".
// Only descriptors that link to /dev/net/tun are read, which skips almost
// every descriptor of every process. Processes that vanish or cannot be
// inspected are skipped, and so are processes in another network namespace:
// fdinfo gives only the interface's name, and names are per namespace, so a
// container's tun0 says nothing about the host's.
func tunOwnerPIDs(procRoot, iface string) []int {
	entries, err := os.ReadDir(procRoot)
	if err != nil {
		return nil
	}
	ownNetns, _ := os.Readlink(filepath.Join(procRoot, "self", "ns", "net"))
	var pids []int
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid <= 0 {
			continue
		}
		if ownNetns != "" {
			if netns, err := os.Readlink(filepath.Join(procRoot, e.Name(), "ns", "net")); err != nil || netns != ownNetns {
				continue
			}
		}
		if holdsTun(filepath.Join(procRoot, e.Name()), iface) {
			pids = append(pids, pid)
		}
	}
	sort.Ints(pids)
	return pids
}

// holdsTun reports whether the process at procDir has a tun descriptor for iface.
func holdsTun(procDir, iface string) bool {
	fds, err := os.ReadDir(filepath.Join(procDir, "fd"))
	if err != nil {
		return false
	}
	for _, fd := range fds {
		target, err := os.Readlink(filepath.Join(procDir, "fd", fd.Name()))
		if err != nil || target != tunDevicePath {
			continue
		}
		info, err := os.ReadFile(filepath.Join(procDir, "fdinfo", fd.Name()))
		if err != nil {
			continue
		}
		if tunIfaceFromFdinfo(string(info)) == iface {
			return true
		}
	}
	return false
}

// tunIfaceFromFdinfo returns the interface named by the "iff:" line of a
// descriptor's fdinfo, or "" when there is none.
func tunIfaceFromFdinfo(fdinfo string) string {
	for line := range strings.SplitSeq(fdinfo, "\n") {
		if name, ok := strings.CutPrefix(line, "iff:"); ok {
			return strings.TrimSpace(name)
		}
	}
	return ""
}
