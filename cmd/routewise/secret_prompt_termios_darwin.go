//go:build darwin

package main

import "golang.org/x/sys/unix"

// termiosGet and termiosSet are the ioctl requests that read and write a
// terminal's settings.
const (
	termiosGet = unix.TIOCGETA
	termiosSet = unix.TIOCSETA
)
