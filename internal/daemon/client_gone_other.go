//go:build !windows

package daemon

// isPlatformClientGone has nothing to add to the Unix errors.
func isPlatformClientGone(error) bool { return false }
