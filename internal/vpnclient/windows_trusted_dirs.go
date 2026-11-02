package vpnclient

import "strings"

// underTrustedRoot reports whether the executable at path lives inside one of
// roots. The roots are the directories only administrators can write (Program
// Files, Windows): a client identity is read from the executable's path, so a
// process a standard user started from a folder they control, named openvpn.exe,
// must not be taken for the real client. Both sides are compared in the
// normalized form, which is lower case with backslashes.
func underTrustedRoot(path string, roots []string) bool {
	p := normalizeWindowsPath(path)
	for _, root := range roots {
		r := strings.TrimRight(normalizeWindowsPath(root), `\`)
		if r != "" && strings.HasPrefix(p, r+`\`) {
			return true
		}
	}
	return false
}

// mayBeClientExe is the cheap first test on a process's bare file name, before
// any process is opened: it passes every name IsClientExe can accept from a full
// path, including the AWS VPN Client's own executables, which are recognised by
// their directory rather than their name.
func mayBeClientExe(exeFile string) bool {
	name := strings.ToLower(exeFile)
	return familyOf(name) != familyNone ||
		strings.Contains(name, "openvpn") || strings.Contains(name, "awsvpn") ||
		strings.Contains(name, "acvc") || strings.Contains(name, "aws")
}
