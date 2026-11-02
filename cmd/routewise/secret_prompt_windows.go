//go:build windows

package main

import (
	"fmt"
	"io"
	"os"

	"golang.org/x/sys/windows"
)

// isTerminal reports whether f is a console: only a console handle answers
// GetConsoleMode.
func isTerminal(f *os.File) bool {
	var mode uint32
	return windows.GetConsoleMode(windows.Handle(f.Fd()), &mode) == nil
}

// promptHidden writes prompt to out and reads one line from the console f with
// echo switched off (ENABLE_ECHO_INPUT cleared), so a secret typed or pasted
// there is neither shown nor left in the scrollback. Line input and processed
// input stay on so editing keys and Ctrl+C still work; the original mode is
// restored on every exit.
func promptHidden(f *os.File, out io.Writer, prompt string) (string, error) {
	handle := windows.Handle(f.Fd())
	line, err := readHiddenLine(f, out, prompt, func() (func(), error) {
		var old uint32
		if err := windows.GetConsoleMode(handle, &old); err != nil {
			return nil, fmt.Errorf("read console settings: %w", err)
		}
		if err := windows.SetConsoleMode(handle, old&^windows.ENABLE_ECHO_INPUT); err != nil {
			return nil, fmt.Errorf("turn console echo off: %w", err)
		}
		return func() { _ = windows.SetConsoleMode(handle, old) }, nil
	})
	return line, err
}
