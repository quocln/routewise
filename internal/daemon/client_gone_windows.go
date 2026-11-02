//go:build windows

package daemon

import (
	"errors"

	"golang.org/x/sys/windows"
)

// isPlatformClientGone recognises the errors a named pipe reports when its
// client closed it: the pipe is broken, closing, or no longer connected.
func isPlatformClientGone(err error) bool {
	return errors.Is(err, windows.ERROR_BROKEN_PIPE) ||
		errors.Is(err, windows.ERROR_NO_DATA) ||
		errors.Is(err, windows.ERROR_PIPE_NOT_CONNECTED)
}
