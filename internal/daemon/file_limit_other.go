//go:build !unix

package daemon

import "log/slog"

// RaiseFileLimit does nothing: only Unix systems have a per-process open file
// limit to raise.
func RaiseFileLimit(*slog.Logger) {}
