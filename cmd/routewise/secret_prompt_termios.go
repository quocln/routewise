//go:build darwin || linux

package main

import (
	"fmt"
	"io"
	"os"

	"golang.org/x/sys/unix"
)

// isTerminal reports whether f is a terminal.
func isTerminal(f *os.File) bool {
	_, err := unix.IoctlGetTermios(int(f.Fd()), termiosGet)
	return err == nil
}

// promptHidden writes prompt to out and reads one line from the terminal f with
// echo switched off, so a secret typed or pasted there is neither shown nor left
// in the scrollback. The terminal is restored on every exit, including an
// interrupt, which would otherwise leave the user's shell not echoing.
func promptHidden(f *os.File, out io.Writer, prompt string) (string, error) {
	fd := int(f.Fd())
	return readHiddenLine(f, out, prompt, func() (func(), error) {
		old, err := unix.IoctlGetTermios(fd, termiosGet)
		if err != nil {
			return nil, fmt.Errorf("read terminal settings: %w", err)
		}
		quiet := *old
		quiet.Lflag &^= unix.ECHO
		if err := unix.IoctlSetTermios(fd, termiosSet, &quiet); err != nil {
			return nil, fmt.Errorf("turn terminal echo off: %w", err)
		}
		return func() { _ = unix.IoctlSetTermios(fd, termiosSet, old) }, nil
	})
}
