//go:build windows

package main

import "golang.org/x/sys/windows"

// isPrivileged reports whether the process runs with an elevated token (an
// administrator in an elevated prompt, or SYSTEM). A standard user, or an
// administrator whose prompt was not started with "Run as administrator",
// has a filtered token and is not.
func isPrivileged() bool { return windows.GetCurrentProcessToken().IsElevated() }
