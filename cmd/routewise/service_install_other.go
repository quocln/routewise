//go:build !linux && !windows

package main

import "github.com/quocln/routewise/internal/platform"

// installService reports that self-install is not available here: macOS
// installs the helper with `sudo make install`.
func installService() error { return platform.Unsupported("service install") }

// uninstallService reports that self-uninstall is not available here.
func uninstallService() error { return platform.Unsupported("service uninstall") }
