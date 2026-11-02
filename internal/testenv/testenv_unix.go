//go:build !windows

package testenv

import (
	"net"
	"testing"
)

func listenLocal(t *testing.T) (net.Listener, string, error) {
	sock, err := shortTempSocket(t)
	if err != nil {
		return nil, "", err
	}
	l, err := net.Listen("unix", sock)
	return l, sock, err
}

// RunProtected runs the tests. Only Windows judges a temp file by its access
// list; see the Windows version.
func RunProtected(m *testing.M) int { return m.Run() }
