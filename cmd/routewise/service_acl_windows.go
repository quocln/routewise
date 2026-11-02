//go:build windows

package main

import (
	"errors"
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/quocln/routewise/internal/platform"
)

// ensureProtectedDir makes path a directory with the access list sddl and
// SYSTEM-or-Administrators ownership.
//
// A new directory is created with the access list already attached
// (CreateDirectory with security attributes), so there is no moment when it
// exists with ProgramData's permissive defaults. A directory that already
// exists is trusted only when it is a real directory owned by SYSTEM or
// Administrators: ProgramData lets any user create folders, so a standard user
// could have pre-created RouteWise and kept ownership, which would let them
// rewrite the access list later. Such a directory is refused rather than
// taken over.
func ensureProtectedDir(path, sddl string) error {
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return fmt.Errorf("access list %q: %w", sddl, err)
	}
	pathPtr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	attrs := &windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: sd,
	}
	err = windows.CreateDirectory(pathPtr, attrs)
	if err == nil {
		return nil
	}
	if !errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		return fmt.Errorf("create %s: %w", path, err)
	}

	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect %s: %w", path, err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || isReparsePoint(info) {
		return fmt.Errorf("%s exists and is not a plain directory; remove it and run the install again", path)
	}
	current, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("read the owner of %s: %w", path, err)
	}
	owner, _, err := current.Owner()
	if err != nil || owner == nil || !platform.TrustedOwnerSID(owner.String()) {
		return fmt.Errorf("%s already exists and is not owned by SYSTEM or Administrators; "+
			"remove it (or run: icacls \"%s\" /setowner Administrators) and run the install again", path, path)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return fmt.Errorf("access list %q: %w", sddl, err)
	}
	// PROTECTED stops the directory inheriting from ProgramData; the call also
	// pushes the inheritable entries down to what is already inside.
	err = windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
	if err != nil {
		return fmt.Errorf("set the access list of %s: %w", path, err)
	}
	return nil
}
