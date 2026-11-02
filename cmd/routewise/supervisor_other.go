//go:build !windows

package main

// runSupervised runs the daemon in the foreground: launchd and systemd start
// it as a plain process and stop it with a signal.
func runSupervised(start helperStart) error { return runForeground(start) }
