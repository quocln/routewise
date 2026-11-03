package vpnclient

import (
	"bytes"
	"cmp"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
)

// ErrNotAVPNClient says a chosen program cannot be matched to a tunnel, so
// allowing it would leave an entry that never connects.
var ErrNotAVPNClient = errors.New("not a VPN client RouteWise can recognize")

// Scan lists the VPN clients installed on this machine, under the same IDs
// Identify gives them once they own a tunnel. A result is a candidate: nothing
// here proves the client will create a full tunnel, which only connecting does.
func Scan() []Client { return sortedUnique(scanInstalled()) }

// ResolveInstalled returns the client a program the user chose stands for. An
// app is rarely what owns its tunnel, so the path chosen and the ID returned
// usually differ.
func ResolveInstalled(path string) (Client, error) {
	if !filepath.IsAbs(path) {
		return Client{}, fmt.Errorf("%w: %q is not an absolute path", ErrNotAVPNClient, path)
	}
	return resolveInstalled(path)
}

// ClientForID returns the client an allowlist entry stands for, named as
// Identify would name it. It works from the ID alone, so a client that has never
// connected and one that has read the same.
func ClientForID(id string) Client {
	if id == KernelWireGuard.ID {
		return KernelWireGuard
	}
	c := FromPath(id)
	switch runtime.GOOS {
	case "linux":
		c.Name = FromLinuxExe(id).Name
	case "windows":
		if f := familyOf(normalizeWindowsPath(id)); f != familyNone {
			c.Name = f.displayName()
		}
	}
	return c
}

func sortedUnique(clients []Client) []Client {
	slices.SortFunc(clients, func(a, b Client) int {
		return cmp.Or(cmp.Compare(a.Name, b.Name), cmp.Compare(a.ID, b.ID))
	})
	return slices.CompactFunc(clients, func(a, b Client) bool { return a.ID == b.ID })
}

func isExecutableFile(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular() && info.Mode().Perm()&0o111 != 0
}

// isScript reports whether path starts with "#!". A script never owns a tunnel:
// the process that does is its interpreter or a program it starts.
func isScript(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	head := make([]byte, 2)
	_, err = io.ReadFull(f, head)
	return err == nil && bytes.Equal(head, []byte("#!"))
}

// chosenProgram resolves links in a path the user chose and checks it is a
// program that can own a tunnel.
func chosenProgram(path string) (string, error) {
	real, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", fmt.Errorf("%w: cannot read %q", ErrNotAVPNClient, path)
	}
	if !isExecutableFile(real) {
		return "", fmt.Errorf("%w: %q is not a program", ErrNotAVPNClient, path)
	}
	if isScript(real) {
		return "", fmt.Errorf("%w: %q is a script; choose the program it starts", ErrNotAVPNClient, path)
	}
	return real, nil
}
