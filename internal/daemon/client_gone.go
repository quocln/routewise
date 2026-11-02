package daemon

import (
	"errors"
	"syscall"
)

// isClientGone reports whether a write failed because the client hung up.
func isClientGone(err error) bool {
	return errors.Is(err, syscall.EPIPE) || errors.Is(err, syscall.ECONNRESET) || isPlatformClientGone(err)
}
