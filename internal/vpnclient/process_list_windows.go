package vpnclient

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

// runningClientProcesses lists the processes that can own a VPN tunnel (see
// IsClientExe), with their command lines. A process that cannot be opened or
// whose command line cannot be read is listed without it or skipped: a client
// the helper cannot inspect simply is not identified.
func runningClientProcesses(ctx context.Context) ([]Process, error) {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, fmt.Errorf("list processes: %w", err)
	}
	defer windows.CloseHandle(snap)

	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))
	err = windows.Process32First(snap, &entry)
	var procs []Process
	pathBuf := make([]uint16, windows.MAX_LONG_PATH) // reused for every process
	for ; err == nil; err = windows.Process32Next(snap, &entry) {
		if cerr := ctx.Err(); cerr != nil {
			return nil, cerr
		}
		// Most processes are no client; their file name says so without opening
		// them.
		if !mayBeClientExe(windows.UTF16ToString(entry.ExeFile[:])) {
			continue
		}
		if p, ok := inspectProcess(entry.ProcessID, pathBuf); ok {
			procs = append(procs, p)
		}
	}
	if !errors.Is(err, windows.ERROR_NO_MORE_FILES) {
		return nil, fmt.Errorf("list processes: %w", err)
	}
	return procs, nil
}

// trustedClientRoots are the directories a client executable must be installed
// under: Program Files (both architectures) and Windows. Standard users cannot
// write to any of them.
var trustedClientRoots = sync.OnceValue(func() []string {
	var roots []string
	for _, id := range []*windows.KNOWNFOLDERID{windows.FOLDERID_ProgramFiles, windows.FOLDERID_ProgramFilesX86, windows.FOLDERID_Windows} {
		if p, err := windows.KnownFolderPath(id, windows.KF_FLAG_DEFAULT); err == nil {
			roots = append(roots, p)
		}
	}
	return roots
})

// inspectProcess reads the executable path of pid into buf and, for a VPN
// client executable, its command line.
func inspectProcess(pid uint32, buf []uint16) (Process, bool) {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return Process{}, false
	}
	defer windows.CloseHandle(h)

	size := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(h, 0, &buf[0], &size); err != nil {
		return Process{}, false
	}
	path := windows.UTF16ToString(buf[:size])
	// Only an executable an administrator installed can stand for a client; see
	// underTrustedRoot.
	if !IsClientExe(path) || !underTrustedRoot(path, trustedClientRoots()) {
		return Process{}, false
	}
	return Process{Path: path, CmdLine: processCommandLine(h)}, true
}

// processCommandLine reads a process's command line with
// NtQueryInformationProcess(ProcessCommandLineInformation), which needs only
// limited query access and no read of the process's memory. It returns "" when
// the line cannot be read.
func processCommandLine(h windows.Handle) string {
	buf := make([]byte, 2048)
	for range 3 {
		var need uint32
		err := windows.NtQueryInformationProcess(h, windows.ProcessCommandLineInformation, unsafe.Pointer(&buf[0]), uint32(len(buf)), &need)
		if err == nil {
			// The answer is a UNICODE_STRING whose text follows it in buf.
			return (*windows.NTUnicodeString)(unsafe.Pointer(&buf[0])).String()
		}
		status, ok := err.(windows.NTStatus)
		if !ok || (status != windows.STATUS_BUFFER_OVERFLOW && status != windows.STATUS_INFO_LENGTH_MISMATCH && status != windows.STATUS_BUFFER_TOO_SMALL) || int(need) <= len(buf) {
			return ""
		}
		buf = make([]byte, need)
	}
	return ""
}
