//go:build !windows

package main

import (
	"os"
	"syscall"
)

// isReparsePoint is always false: only Windows has reparse points (junctions,
// mount points, cloud placeholders); symlinks are checked by mode elsewhere.
func isReparsePoint(os.FileInfo) bool { return false }

// openNoFollow opens path for reading and fails when its last element is a
// symlink, so the file read is the one that was inspected through the handle.
func openNoFollow(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
}
