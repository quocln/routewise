package vpnclient

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// The macOS rules live in this untagged file so they compile and run on every
// Unix developer machine; the darwin build selects them in
// installed_clients_darwin.go.
//
// A system extension is left out on purpose: it runs from
// /Library/SystemExtensions/<uuid>/, and the uuid changes with every update, so
// the path found now would stop matching. Those clients still get the offer
// when they connect.

// packetTunnelExtensionPoint marks the kind of NetworkExtension that holds a
// utun. App proxies and content filters use other points and own no tunnel.
const packetTunnelExtensionPoint = "com.apple.networkextension.packet-tunnel"

// maxInfoPlist bounds what is read from a bundle. The helper reads these as
// root, and an app under a user's folder can hold anything.
const maxInfoPlist = 1 << 20

// macCommandLineClients are the binaries that hold a utun themselves, and
// macBinaryDirs where Homebrew links them.
var (
	macCommandLineClients = []string{"openvpn", "wireguard-go"}
	macBinaryDirs         = []string{"/opt/homebrew/sbin", "/opt/homebrew/bin", "/usr/local/sbin", "/usr/local/bin"}
)

// scanMac lists the clients under root, which is "/" outside tests.
func scanMac(root string) []Client {
	var found []Client
	dirs := []string{filepath.Join(root, "Applications")}
	if homes, err := filepath.Glob(filepath.Join(root, "Users", "*", "Applications")); err == nil {
		dirs = append(dirs, homes...)
	}
	for _, app := range macAppBundles(dirs) {
		found = append(found, macAppClients(app)...)
	}
	for _, dir := range macBinaryDirs {
		for _, name := range macCommandLineClients {
			real, err := filepath.EvalSymlinks(filepath.Join(root, dir, name))
			if err == nil && isExecutableFile(real) {
				found = append(found, FromPath(real))
			}
		}
	}
	return found
}

// macAppBundles lists the apps in dirs and one folder down, where the AWS VPN
// Client installs itself ("/Applications/AWS VPN Client/AWS VPN Client.app").
func macAppBundles(dirs []string) []string {
	var apps []string
	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			path := filepath.Join(dir, e.Name())
			if strings.HasSuffix(e.Name(), ".app") {
				apps = append(apps, path)
				continue
			}
			if !e.IsDir() {
				continue
			}
			nested, err := os.ReadDir(path)
			if err != nil {
				continue
			}
			for _, n := range nested {
				if strings.HasSuffix(n.Name(), ".app") {
					apps = append(apps, filepath.Join(path, n.Name()))
				}
			}
		}
	}
	return apps
}

// macAppClients returns the programs inside app that hold a tunnel: its packet
// tunnel extensions, and the OpenVPN the AWS VPN Client ships.
func macAppClients(app string) []Client {
	var found []Client
	plugins, _ := os.ReadDir(filepath.Join(app, "Contents", "PlugIns"))
	for _, p := range plugins {
		if !strings.HasSuffix(p.Name(), ".appex") && !strings.HasSuffix(p.Name(), ".app") {
			continue
		}
		if exe, ok := macTunnelExtensionExe(filepath.Join(app, "Contents", "PlugIns", p.Name())); ok {
			found = append(found, FromPath(exe))
		}
	}
	aws := filepath.Join(app, "Contents", "Resources", "openvpn", "acvc-openvpn")
	if isExecutableFile(aws) {
		found = append(found, FromPath(aws))
	}
	return found
}

// macTunnelExtensionExe returns the executable of a packet tunnel extension. The
// extension point is found in the raw bytes, since a binary plist stores ASCII
// strings as they are. The name is taken from Contents/MacOS rather than
// CFBundleExecutable, which would take a plist parser: a bundle's executable is
// named after it or is the only one there.
func macTunnelExtensionExe(bundle string) (string, bool) {
	f, err := os.Open(filepath.Join(bundle, "Contents", "Info.plist"))
	if err != nil {
		return "", false
	}
	defer f.Close()
	info, err := io.ReadAll(io.LimitReader(f, maxInfoPlist))
	if err != nil || !bytes.Contains(info, []byte(packetTunnelExtensionPoint)) {
		return "", false
	}

	dir := filepath.Join(bundle, "Contents", "MacOS")
	named := filepath.Join(dir, strings.TrimSuffix(filepath.Base(bundle), filepath.Ext(bundle)))
	if isExecutableFile(named) {
		return named, true
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", false
	}
	var executables []string
	for _, e := range entries {
		if path := filepath.Join(dir, e.Name()); isExecutableFile(path) {
			executables = append(executables, path)
		}
	}
	if len(executables) != 1 {
		return "", false
	}
	return executables[0], true
}

// resolveMacClient accepts an app, an extension, or a program.
func resolveMacClient(path string) (Client, error) {
	real, err := filepath.EvalSymlinks(path)
	if err != nil {
		return Client{}, fmt.Errorf("%w: cannot read %q", ErrNotAVPNClient, path)
	}
	switch {
	case strings.HasSuffix(real, ".appex"):
		if exe, ok := macTunnelExtensionExe(real); ok {
			return FromPath(exe), nil
		}
		return Client{}, fmt.Errorf("%w: %q is not a VPN extension", ErrNotAVPNClient, path)
	case strings.HasSuffix(real, ".app"):
		return macBundleClient(real, path)
	}
	// An app's main binary is its window, not its tunnel.
	if app, _, inApp := strings.Cut(real, ".app/Contents/MacOS/"); inApp {
		return macBundleClient(app+".app", path)
	}
	program, err := chosenProgram(real)
	if err != nil {
		return Client{}, err
	}
	return FromPath(program), nil
}

func macBundleClient(app, chosen string) (Client, error) {
	clients := sortedUnique(macAppClients(app))
	if len(clients) == 0 {
		return Client{}, fmt.Errorf("%w: %q has no VPN extension. If it uses a system extension, connect it and RouteWise will offer to manage it", ErrNotAVPNClient, chosen)
	}
	return clients[0], nil
}
