package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// The file-level steps of `routewise service install`, kept free of systemctl
// and root checks so they can be exercised anywhere.

// systemdUnit renders the helper's unit. The daemon runs in the foreground
// under systemd, which restarts it after a crash and orders it after the
// network and the resolver whose per-link DNS it configures.
//
// The helper stays root but is confined to what it does: it may write only its
// own directories (config, database, logs, and /run for the socket, pid file
// and journals), and its capability set is exactly what it uses: netlink routes
// and links (NET_ADMIN, which also creates tun devices), the AF_PACKET capture
// (NET_RAW), the DNS forwarder's port 53 (NET_BIND_SERVICE), and reading
// /proc/PID/{exe,fd,fdinfo} of other users' processes to identify a VPN client
// (SYS_PTRACE for the access check, DAC_READ_SEARCH for the 0400 fdinfo files).
func systemdUnit(binaryPath, configPath string) string {
	return fmt.Sprintf(`[Unit]
Description=RouteWise helper: per-domain VPN routing
After=network-online.target systemd-resolved.service
Wants=network-online.target

[Service]
Type=simple
ExecStart=%s start --foreground --config %s
Restart=on-failure
RestartSec=2
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=/etc/routewise /var/lib/routewise /var/log/routewise /run
ProtectHome=read-only
PrivateTmp=yes
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE CAP_SYS_PTRACE CAP_DAC_READ_SEARCH

[Install]
WantedBy=multi-user.target
`, binaryPath, configPath)
}

// starterConfig is the configuration a fresh install starts with. The domain
// list is left empty: the user adds theirs in the app or with
// `routewise add-domain`.
func starterConfig(pidFile, logFile string) string {
	return fmt.Sprintf(`# RouteWise Configuration
#
# These are starter defaults. RouteWise only installs this file when no
# configuration exists yet; an existing configuration is never overwritten.
# Edit your domains in the RouteWise app, or with `+"`routewise add-domain`"+`.

# Domain patterns to route through the VPN (one per line)
# Wildcards match exactly one label: "*.example.com" matches api.example.com,
# not example.com or a.b.example.com.
domains: []

# Routing behavior
routing:
  # How RouteWise coexists with the VPN client:
  #   "inverted" (default) - removes VPN catch-all routes, only configured domains go through VPN
  #   "additive"           - keeps VPN routes intact, adds /32 routes alongside
  mode: "inverted"

# DNS resolver settings
dns:
  # DNS servers to use for domain resolution
  # All servers are queried and IPs merged (handles CDN/GeoDNS like CloudFront)
  servers:
    - "1.1.1.1"
    - "8.8.8.8"
  # Cache TTL in seconds (5 minutes default - handles CloudFront IP rotation)
  cache_ttl: 300
  # Resolve through the DNS servers the VPN pushes while it is connected.
  use_vpn_dns: false

# Daemon settings
daemon:
  # VPN interface polling interval in seconds
  poll_interval: 1
  pid_file: %q
  log_file: %q
  # Log level: debug, info, warn, error
  log_level: "info"
`, pidFile, logFile)
}

// replaceFile writes content to path through a temporary file in the same
// directory and a rename, so a reader or a crash sees the old file or the new
// one and never a partial one. Whatever sits at path, a symlink included, is
// replaced, never written through.
func replaceFile(path string, mode os.FileMode, write func(io.Writer) error) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return fmt.Errorf("create temporary file in %s: %w", dir, err)
	}
	tmpPath := tmp.Name()
	fail := func(err error) error {
		tmp.Close()
		os.Remove(tmpPath)
		return err
	}
	if err := write(tmp); err != nil {
		return fail(fmt.Errorf("write %s: %w", path, err))
	}
	if err := tmp.Chmod(mode); err != nil {
		return fail(fmt.Errorf("set mode of %s: %w", path, err))
	}
	if err := tmp.Sync(); err != nil {
		return fail(fmt.Errorf("flush %s: %w", path, err))
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("close %s: %w", path, err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("replace %s: %w", path, err)
	}
	return nil
}

// installExecutable copies the executable at src to dst (mode 0755). The source
// must be a regular file reached without a symlink: the copy ends up running as
// root, so it must be exactly the file the caller meant. The source is opened
// without following a symlink and inspected through that open file, then copied
// from it, so nothing can be swapped in between the check and the copy.
func installExecutable(src, dst string) error {
	in, err := openNoFollow(src)
	if err != nil {
		return fmt.Errorf("open %s (a symlink is refused): %w", src, err)
	}
	defer in.Close()
	info, err := in.Stat()
	if err != nil {
		return fmt.Errorf("inspect %s: %w", src, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s is a symlink; refusing to install it", src)
	}
	if !info.Mode().IsRegular() || isReparsePoint(info) {
		return fmt.Errorf("%s is not a regular file; refusing to install it", src)
	}
	return replaceFile(dst, 0o755, func(w io.Writer) error {
		_, err := io.Copy(w, in)
		return err
	})
}

// seedConfig installs the starter configuration unless the helper already has
// one: an existing config.yaml or an existing database (which holds the
// configuration once the helper has run). It reports whether it wrote the file.
func seedConfig(configPath, dbPath, content string) (bool, error) {
	for _, existing := range []string{configPath, dbPath} {
		if _, err := os.Lstat(existing); err == nil {
			return false, nil
		} else if !os.IsNotExist(err) {
			return false, fmt.Errorf("inspect %s: %w", existing, err)
		}
	}
	err := replaceFile(configPath, 0o644, func(w io.Writer) error {
		_, err := io.WriteString(w, content)
		return err
	})
	return err == nil, err
}
