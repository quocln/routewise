//go:build windows

package main

import (
	"os"
	"syscall"
)

// isReparsePoint reports whether the file is a reparse point of any kind. Go
// reports symlinks and junctions by mode, but other reparse points (cloud
// files, dedup stubs) look regular, and the file about to be copied into a
// SYSTEM-owned location must be exactly the bytes on disk.
func isReparsePoint(info os.FileInfo) bool {
	data, ok := info.Sys().(*syscall.Win32FileAttributeData)
	return ok && data.FileAttributes&syscall.FILE_ATTRIBUTE_REPARSE_POINT != 0
}

// openNoFollow opens path for reading without following a symlink or junction:
// the handle is the link itself, which isReparsePoint then reports.
func openNoFollow(path string) (*os.File, error) {
	name, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	h, err := syscall.CreateFile(name, syscall.GENERIC_READ, syscall.FILE_SHARE_READ, nil,
		syscall.OPEN_EXISTING, syscall.FILE_ATTRIBUTE_NORMAL|syscall.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	return os.NewFile(uintptr(h), path), nil
}
