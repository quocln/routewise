//go:build windows

package route

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

// The OS-neutral journal tests keep their files in a user temp directory, which
// the real check rightly refuses. They run against a pass-through; the tests
// below exercise the real check directly.
func init() {
	journalFileSecurityCheck = func(string, os.FileInfo) error { return nil }
}

func TestJournalSecurityRejectsFileEveryoneCanWrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "transition.json")
	if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	everyone, err := windows.CreateWellKnownSid(windows.WinWorldSid)
	if err != nil {
		t.Fatal(err)
	}
	dacl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{{
		AccessPermissions: windows.GENERIC_ALL,
		AccessMode:        windows.GRANT_ACCESS,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  windows.TRUSTEE_IS_WELL_KNOWN_GROUP,
			TrusteeValue: windows.TrusteeValueFromSID(everyone),
		},
	}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := checkJournalFileSecurity(path, info); !errors.Is(err, ErrJournalInsecureMode) {
		t.Fatalf("expected ErrJournalInsecureMode, got %v", err)
	}
}

func TestSyncJournalDirIsNoOp(t *testing.T) {
	if err := syncJournalDir(t.TempDir()); err != nil {
		t.Fatalf("syncJournalDir: %v", err)
	}
}
