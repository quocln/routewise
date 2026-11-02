//go:build !windows

package main

import "os"

// isPrivileged reports whether the process is root.
func isPrivileged() bool { return os.Geteuid() == 0 }
