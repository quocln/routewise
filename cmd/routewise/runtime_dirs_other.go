//go:build !windows

package main

// protectRuntimeDirs does nothing here: the installer creates the Unix
// directories root-owned and the config security check covers the rest.
func protectRuntimeDirs(string) error { return nil }
