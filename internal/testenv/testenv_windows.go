//go:build windows

package testenv

import (
	"fmt"
	"net"
	"os"
	"testing"

	"golang.org/x/sys/windows"

	"github.com/quocln/routewise/internal/ipc"
)

// listenLocal listens on a pipe of its own: the real client refuses anything
// but a named pipe here, and the helper's own name must stay free. The client
// also refuses a server that is not elevated, so these tests need an elevated
// shell, which CI is.
func listenLocal(t *testing.T) (net.Listener, string, error) {
	sock, err := shortTempSocket(t)
	if err != nil {
		return nil, "", err
	}
	address := fmt.Sprintf(`\\.\pipe\routewise-test-%d-%x`, os.Getpid(), sock)
	l, err := ipc.Listen(address)
	return l, address, err
}

// RunProtected runs the tests with TMP inside a directory only SYSTEM and
// Administrators can write, as the helper's data directory is. The helper
// refuses a config or journal an ordinary user can modify, and a user temp
// directory is exactly that, so this keeps the real check running without a way
// to turn it off. It needs an elevated shell: without one the tests that persist
// a config report the security error.
func RunProtected(m *testing.M) int {
	dir, err := protectedTempDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "protected temp directory: %v\n", err)
		return 1
	}
	defer os.RemoveAll(dir)
	return m.Run()
}

func protectedTempDir() (string, error) {
	dir, err := os.MkdirTemp("", "rwtest")
	if err != nil {
		return "", err
	}
	// Protected, and inherited by everything created inside.
	sd, err := windows.SecurityDescriptorFromString("D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")
	if err != nil {
		return "", err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return "", err
	}
	if err := windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil); err != nil {
		return "", err
	}
	for _, name := range []string{"TMP", "TEMP"} {
		if err := os.Setenv(name, dir); err != nil {
			return "", err
		}
	}
	return dir, nil
}
