//go:build !darwin && !linux && !windows

package main

import (
	"errors"
	"io"
	"os"
)

// isTerminal is false here: a build for this system reads the key from
// standard input.
func isTerminal(*os.File) bool { return false }

func promptHidden(*os.File, io.Writer, string) (string, error) {
	return "", errors.New("a hidden prompt is not available on this system; pipe the key in")
}
