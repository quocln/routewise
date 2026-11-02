//go:build unix

package daemon

import (
	"log/slog"
	"syscall"
)

// wantedOpenFiles is the soft RLIMIT_NOFILE the helper asks for. Every
// proxied Outline flow holds a socket, and launchd's default soft limit is
// often 256.
const wantedOpenFiles = 8192

// RaiseFileLimit lifts the soft open-file limit toward wantedOpenFiles without
// touching the hard limit, and logs the result. A failure is logged and
// otherwise ignored: the helper still works, with fewer simultaneous flows.
func RaiseFileLimit(logger *slog.Logger) {
	var lim syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &lim); err != nil {
		logger.Warn("could not read the open file limit", "error", err)
		return
	}
	before := lim.Cur
	target := uint64(wantedOpenFiles)
	if lim.Max < target {
		target = lim.Max
	}
	if lim.Cur >= target {
		logger.Info("open file limit", "soft", lim.Cur, "hard", lim.Max)
		return
	}
	lim.Cur = target
	if err := syscall.Setrlimit(syscall.RLIMIT_NOFILE, &lim); err != nil {
		// macOS caps the soft limit at OPEN_MAX (10240) however high the hard
		// limit reads, so a request can be refused; fall back to that.
		lim.Cur = min(target, 10240)
		if err2 := syscall.Setrlimit(syscall.RLIMIT_NOFILE, &lim); err2 != nil {
			logger.Warn("could not raise the open file limit", "soft", before, "wanted", target, "error", err)
			return
		}
	}
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &lim); err == nil {
		logger.Info("raised the open file limit", "from", before, "soft", lim.Cur, "hard", lim.Max)
	}
}
