//go:build darwin

package vpnclient

import (
	"bufio"
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// Absolute tool paths: the daemon runs as root and never resolves through PATH.
const (
	lsofPath = "/usr/sbin/lsof"
	psPath   = "/bin/ps"
)

// identifyTimeout bounds one identification; lsof over every process takes a
// few hundred milliseconds.
const identifyTimeout = 5 * time.Second

// lsofArgs lists open files as `p<pid>` and `n<name>` lines, skipping the
// descriptors that can never be a utun control socket (working directory,
// executable text, root directory, memory-mapped files). Those are most of the
// rows, so the scan is much cheaper; the sockets are all numbered descriptors.
var lsofArgs = []string{"-nP", "-F", "pn", "-d", "^cwd,^txt,^rtd,^mem"}

// Identify returns the client that owns iface (for example "utun6").
func Identify(ctx context.Context, iface string) (Client, error) {
	ctx, cancel := context.WithTimeout(ctx, identifyTimeout)
	defer cancel()

	// lsof exits non-zero when some file cannot be inspected, while still
	// printing everything it could, so its output is used regardless.
	out, _ := exec.CommandContext(ctx, lsofPath, lsofArgs...).Output()
	pid, ok := utunOwners(string(out))[iface]
	if !ok {
		return Client{}, fmt.Errorf("no process owns %s", iface)
	}

	path, err := exec.CommandContext(ctx, psPath, "-o", "comm=", "-p", strconv.Itoa(pid)).Output()
	if err != nil {
		return Client{}, fmt.Errorf("executable of pid %d: %w", pid, err)
	}
	rememberOwner(iface, pid)
	return FromPath(strings.TrimSpace(string(path))), nil
}

// utunOwners maps each utun interface to the pid holding its control socket,
// from `lsof -F pn` output. A control socket's name reads
// "[ctl com.apple.net.utun_control id 5 unit 7]", and unit N is utun(N-1).
func utunOwners(output string) map[string]int {
	owners := make(map[string]int)
	pid := 0
	scanner := bufio.NewScanner(strings.NewReader(output))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		switch line[0] {
		case 'p':
			pid, _ = strconv.Atoi(line[1:])
		case 'n':
			if pid == 0 || !strings.Contains(line, "com.apple.net.utun_control") {
				continue
			}
			fields := strings.Fields(strings.Trim(line[1:], "[]"))
			for i := 0; i+1 < len(fields); i++ {
				if fields[i] != "unit" {
					continue
				}
				if unit, err := strconv.Atoi(fields[i+1]); err == nil && unit > 0 {
					owners[fmt.Sprintf("utun%d", unit-1)] = pid
				}
			}
		}
	}
	return owners
}
