package platform

import "strings"

// The Windows file layout and the ACL rules around it are plain string logic,
// kept free of Win32 calls so they can be tested on any OS. The windows-only
// files feed them the real environment.

// windowsPaths is where the helper keeps its files on Windows: everything under
// %ProgramData%\RouteWise, which only SYSTEM and Administrators may write
// (service install sets that ACL). The database sits beside config.yaml.
type windowsPaths struct {
	root     string
	logDir   string
	runDir   string
	logRoots []string
}

const (
	windowsAppDirName = "RouteWise"
	// defaultProgramData is used when neither the known-folder API nor the
	// environment names the ProgramData directory.
	defaultProgramData = `C:\ProgramData`
)

// windowsLayout derives the layout from the ProgramData directory.
func windowsLayout(programData string) windowsPaths {
	root := winJoin(programData, windowsAppDirName)
	return windowsPaths{
		root:     root,
		logDir:   winJoin(root, "logs"),
		runDir:   winJoin(root, "run"),
		logRoots: []string{root},
	}
}

// winJoin joins Windows path elements with a backslash regardless of the host
// OS, so the layout can be derived and tested anywhere.
func winJoin(elems ...string) string {
	out := strings.TrimRight(elems[0], `\/`)
	for _, e := range elems[1:] {
		out += `\` + strings.Trim(e, `\/`)
	}
	return out
}

// isWindowsAbs reports whether p is a drive-absolute (C:\x) or UNC (\\host\x)
// path.
func isWindowsAbs(p string) bool {
	if len(p) >= 3 && p[1] == ':' && p[2] == '\\' &&
		(p[0] >= 'A' && p[0] <= 'Z' || p[0] >= 'a' && p[0] <= 'z') {
		return true
	}
	return strings.HasPrefix(p, `\\`)
}

// resolveProgramData picks the ProgramData directory: the shell's known folder
// first (it does not depend on the caller's environment), then %ProgramData%,
// then C:\ProgramData. A value that is not an absolute path is ignored.
func resolveProgramData(known func() (string, error), getenv func(string) string) string {
	if known != nil {
		if p, err := known(); err == nil && isWindowsAbs(p) {
			return p
		}
	}
	if p := getenv("ProgramData"); isWindowsAbs(p) {
		return p
	}
	return defaultProgramData
}

// SIDs the ACL rules refer to.
const (
	sidSystem            = "S-1-5-18"
	sidAdministrators    = "S-1-5-32-544"
	sidTrustedInstaller  = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
	sidUsers             = "S-1-5-32-545"
	sidEveryone          = "S-1-1-0"
	sidAuthenticatedUser = "S-1-5-11"
	sidInteractive       = "S-1-5-4"
)

// Access mask bits (winnt.h) that let a principal change a file or directory
// or its security, including the generic rights that map to them.
const (
	fileWriteData    = 0x00000002
	fileAppendData   = 0x00000004
	fileWriteEA      = 0x00000010
	fileDeleteChild  = 0x00000040
	accessDelete     = 0x00010000
	accessWriteDAC   = 0x00040000
	accessWriteOwner = 0x00080000
	genericAll       = 0x10000000
	genericWrite     = 0x40000000

	writeRights = fileWriteData | fileAppendData | fileWriteEA | fileDeleteChild |
		accessDelete | accessWriteDAC | accessWriteOwner | genericAll | genericWrite
)

// GrantsWrite reports whether an access mask lets its holder modify the object
// or its security.
func GrantsWrite(mask uint32) bool { return mask&writeRights != 0 }

// TrustedOwnerSID reports whether sid may own the helper's files and
// directories: only principals that can already do anything to the machine.
func TrustedOwnerSID(sid string) bool {
	switch sid {
	case sidSystem, sidAdministrators, sidTrustedInstaller:
		return true
	}
	return false
}

// accessEntry is one ACE of a DACL reduced to what the policy reads.
type accessEntry struct {
	SID         string
	Mask        uint32
	Deny        bool
	InheritOnly bool // applies to children only, not to the object itself
}

// lowPrivilegeSIDs name the broad groups an unprivileged user belongs to, for
// messages; any other SID is reported as itself.
var lowPrivilegeSIDs = map[string]string{
	sidUsers:             "Users",
	sidEveryone:          "Everyone",
	sidAuthenticatedUser: "Authenticated Users",
	sidInteractive:       "Interactive",
}

// lowPrivilegeWriters names the principals an allow entry lets modify the
// object when they are not SYSTEM, Administrators or TrustedInstaller: a broad
// group, but also one named account, which would be just as able to make the
// helper run what it likes. Deny entries are ignored, so a rule that only looks
// safe because of an earlier deny still fails the check, and so are entries
// that only apply to children (CREATOR OWNER among them: it stands for a
// child's owner, who must already be trusted).
func lowPrivilegeWriters(entries []accessEntry) []string {
	var names []string
	for _, e := range entries {
		if e.Deny || e.InheritOnly || !GrantsWrite(e.Mask) || TrustedOwnerSID(e.SID) {
			continue
		}
		name := lowPrivilegeSIDs[e.SID]
		if name == "" {
			name = e.SID
		}
		names = append(names, name)
	}
	return names
}
