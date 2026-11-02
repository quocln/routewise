//go:build windows

package daemon

import "golang.org/x/sys/windows"

// consoleSessionID returns the session attached to the machine's physical
// display (WTSGetActiveConsoleSessionId). A peer in that session is the user
// at the machine; remote desktop sessions have other ids.
func consoleSessionID() (uint32, error) {
	return validConsoleSession(windows.WTSGetActiveConsoleSessionId())
}
