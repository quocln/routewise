package vpnclient

import (
	"fmt"
	"path/filepath"
	"strings"
)

// The Linux rules live in this untagged file so they run on every Unix developer
// machine; the linux build selects them in installed_clients_linux.go.

const (
	awsClientDir    = "/opt/awsvpnclient/"
	awsClientTunnel = awsClientDir + "Service/Resources/openvpn/acvc-openvpn"
	openVPN3Service = "/usr/libexec/openvpn3-linux/" + openVPN3ServicePrefix + "client"
)

var linuxBinaryDirs = []string{"/usr/sbin", "/usr/bin", "/sbin", "/bin", "/usr/local/sbin", "/usr/local/bin"}

// linuxInstalled reports the real path of a program under root, without root:
// the client rules read absolute paths such as /opt/awsvpnclient/.
func linuxInstalled(root, path string) (string, bool) {
	real, err := filepath.EvalSymlinks(filepath.Join(root, path))
	if err != nil || !isExecutableFile(real) {
		return "", false
	}
	return strings.TrimPrefix(real, root), true
}

// scanLinux lists the clients under root, which is "/" outside tests.
func scanLinux(root string) []Client {
	var found []Client
	for _, dir := range linuxBinaryDirs {
		for _, name := range []string{"openvpn", "wireguard-go"} {
			if exe, ok := linuxInstalled(root, filepath.Join(dir, name)); ok {
				found = append(found, FromLinuxExe(exe))
			}
		}
		// The WireGuard tools drive a kernel link, which has no process of its own.
		if _, ok := linuxInstalled(root, filepath.Join(dir, "wg")); ok {
			found = append(found, KernelWireGuard)
		}
	}
	for _, path := range []string{awsClientTunnel, openVPN3Service} {
		if exe, ok := linuxInstalled(root, path); ok {
			found = append(found, FromLinuxExe(exe))
		}
	}
	return found
}

// resolveLinuxClient maps the front ends people pick to what owns the tunnel.
func resolveLinuxClient(root, path string) (Client, error) {
	real, err := filepath.EvalSymlinks(path)
	if err != nil {
		return Client{}, fmt.Errorf("%w: cannot read %q", ErrNotAVPNClient, path)
	}
	inside := strings.TrimPrefix(real, root)
	switch base := filepath.Base(inside); {
	case base == "wg", base == "wg-quick":
		return KernelWireGuard, nil
	case base == "openvpn3":
		if exe, ok := linuxInstalled(root, openVPN3Service); ok {
			return FromLinuxExe(exe), nil
		}
	case strings.HasPrefix(inside, awsClientDir):
		if exe, ok := linuxInstalled(root, awsClientTunnel); ok {
			return FromLinuxExe(exe), nil
		}
	}
	if _, err := chosenProgram(real); err != nil {
		return Client{}, err
	}
	return FromLinuxExe(inside), nil
}
