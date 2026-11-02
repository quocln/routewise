//go:build windows

package platform

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ACE types whose layout is header, mask, SID (winnt.h). The callback variants
// are conditional grants; they are read as plain grants, the safe direction.
const (
	aceTypeAllowedCallback = 9
	aceTypeDeniedCallback  = 10
	aceInheritOnly         = 0x08
)

// CheckFileSecurity enforces on Windows what the mode and uid checks enforce
// on Unix: the file's owner is SYSTEM or Administrators, and no broad
// group (Users, Everyone, Authenticated Users, Interactive) may modify it.
// The helper runs as SYSTEM, so a file those groups can write is a way to make
// it do anything. A missing file is the caller's business and is not checked
// here. Read access for Users is not an error: the data directory's own ACL
// keeps the database private, and the logs are meant to be readable.
func CheckFileSecurity(path string) error {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("security: read the access rights of %s: %w", path, err)
	}
	if sd == nil {
		return fmt.Errorf("security: %s has no security descriptor", path)
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil {
		return fmt.Errorf("security: %s has no readable owner", path)
	}
	if !TrustedOwnerSID(owner.String()) {
		return fmt.Errorf("security: %s is owned by %s, not SYSTEM or Administrators\n"+
			"  This is a security risk when running as a service.\n"+
			"  Fix with: icacls \"%s\" /setowner Administrators", path, accountName(owner), path)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return fmt.Errorf("security: read the access list of %s: %w", path, err)
	}
	if dacl == nil {
		return fmt.Errorf("security: %s has no access list, so everyone may write it", path)
	}
	entries, err := daclEntries(dacl)
	if err != nil {
		return fmt.Errorf("security: read the access list of %s: %w", path, err)
	}
	if writers := lowPrivilegeWriters(entries); len(writers) > 0 {
		return fmt.Errorf("security: %s can be modified by %s\n"+
			"  This allows an unprivileged user to change daemon behavior.\n"+
			"  Fix with: icacls \"%s\" /inheritance:r /grant:r SYSTEM:(F) Administrators:(F)",
			path, writers[0], path)
	}
	return nil
}

// daclEntries lists the allow and deny entries of a DACL.
func daclEntries(dacl *windows.ACL) ([]accessEntry, error) {
	entries := make([]accessEntry, 0, dacl.AceCount)
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			return nil, err
		}
		var deny bool
		switch ace.Header.AceType {
		case windows.ACCESS_ALLOWED_ACE_TYPE, aceTypeAllowedCallback:
		case windows.ACCESS_DENIED_ACE_TYPE, aceTypeDeniedCallback:
			deny = true
		default:
			continue
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		entries = append(entries, accessEntry{
			SID:         sid.String(),
			Mask:        uint32(ace.Mask),
			Deny:        deny,
			InheritOnly: ace.Header.AceFlags&aceInheritOnly != 0,
		})
	}
	return entries, nil
}

// accountName spells sid as DOMAIN\name for messages, or as the SID itself when
// it does not resolve.
func accountName(sid *windows.SID) string {
	account, domain, _, err := sid.LookupAccount("")
	if err != nil {
		return sid.String()
	}
	return domain + `\` + account
}
