package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
)

// readHiddenLine is the console-independent part of the hidden prompt. echoOff
// switches the console's echo off and returns the function that restores it;
// the restore runs on every exit, an interrupt included, because leaving the
// user's console not echoing is worse than losing the prompt.
func readHiddenLine(f *os.File, out io.Writer, prompt string, echoOff func() (restore func(), err error)) (string, error) {
	restore, err := echoOff()
	if err != nil {
		return "", err
	}
	defer restore()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	finished := make(chan struct{})
	defer func() { signal.Stop(sig); close(finished) }()
	go func() {
		select {
		case <-sig:
			restore()
			fmt.Fprintln(out)
			os.Exit(130)
		case <-finished:
		}
	}()

	fmt.Fprint(out, prompt)
	line, err := bufio.NewReaderSize(io.LimitReader(f, maxProfileSecretBytes+1), 4096).ReadString('\n')
	fmt.Fprintln(out) // the user's Return was not echoed
	if err != nil && !errors.Is(err, io.EOF) {
		return "", fmt.Errorf("read the key: %w", err)
	}
	if len(line) > maxProfileSecretBytes {
		return "", fmt.Errorf("input is larger than %d bytes", maxProfileSecretBytes)
	}
	return line, nil
}
