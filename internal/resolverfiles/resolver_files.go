// Package resolverfiles manages the /etc/resolver/<domain> files that send
// lookups for wildcard domains to RouteWise's local DNS forwarder.
//
// macOS reads every file in /etc/resolver and sends queries for that file's
// domain (and everything under it) to the nameserver and port it names. A file
// left behind after RouteWise stops would point those lookups at a forwarder
// that no longer exists, so every file RouteWise writes starts with a marker
// line: RouteWise only ever rewrites or removes files carrying it, and removes
// all of them on startup, on VPN disconnect, and on shutdown. Files without the
// marker belong to someone else and are never touched.
package resolverfiles

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
)

// Marker is the first line of every resolver file RouteWise owns.
const Marker = "# Managed by RouteWise. Removed automatically when the VPN disconnects."

// domainRegex accepts only plain domain names as file names, so a suffix can
// never escape the resolver directory.
var domainRegex = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}$`)

// ValidDomain reports whether Apply accepts d. One it does not fails the whole call.
func ValidDomain(d string) bool { return domainRegex.MatchString(strings.ToLower(d)) }

// Configurator is the system's split-DNS configuration as the daemon uses it:
// send lookups for a set of domains to RouteWise's local forwarder, and take
// that back. Manager, which writes /etc/resolver files, is the macOS
// implementation; NewSystem returns the one for the running OS.
type Configurator interface {
	// Active returns the domains currently sent to the forwarder.
	Active() []string
	// Apply makes the set of forwarded domains equal to domains and returns
	// the ones it skipped because the system already has its own rule for them.
	Apply(domains []string) (skipped []string, err error)
	// RemoveAll withdraws every rule RouteWise added, including ones a
	// previous process left behind.
	RemoveAll() error
}

var _ Configurator = (*Manager)(nil)

// Manager writes and removes RouteWise-owned resolver files.
type Manager struct {
	dir        string
	nameserver string
	port       int

	mu     sync.Mutex
	active []string
}

// New creates a manager for dir whose files point at nameserver:port.
func New(dir, nameserver string, port int) *Manager {
	return &Manager{dir: dir, nameserver: nameserver, port: port}
}

// Active returns the domains RouteWise currently has resolver files for.
func (m *Manager) Active() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return slices.Clone(m.active)
}

// Apply makes the set of RouteWise-owned resolver files equal to domains. It
// returns the domains it skipped because a file RouteWise does not own already
// exists for them.
func (m *Manager) Apply(domains []string) (skipped []string, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	want := make(map[string]bool, len(domains))
	for _, d := range domains {
		d = strings.ToLower(d)
		if !domainRegex.MatchString(d) {
			return nil, fmt.Errorf("resolver domain %q is not a valid domain name", d)
		}
		want[d] = true
	}

	owned, err := m.ownedLocked()
	if err != nil {
		return nil, err
	}

	var errs []error
	for _, d := range owned {
		if !want[d] {
			if err := os.Remove(filepath.Join(m.dir, d)); err != nil && !os.IsNotExist(err) {
				errs = append(errs, err)
			}
		}
	}

	var active []string
	for _, d := range sortedKeys(want) {
		if !slices.Contains(owned, d) {
			if _, statErr := os.Lstat(filepath.Join(m.dir, d)); statErr == nil {
				skipped = append(skipped, d)
				continue
			}
		}
		if err := m.writeLocked(d); err != nil {
			errs = append(errs, err)
			continue
		}
		active = append(active, d)
	}
	m.active = active

	if len(errs) > 0 {
		return skipped, fmt.Errorf("apply resolver files: %v", errs)
	}
	return skipped, nil
}

// RemoveAll deletes every RouteWise-owned resolver file, including ones a
// previous process left behind.
func (m *Manager) RemoveAll() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	owned, err := m.ownedLocked()
	if err != nil {
		return err
	}
	var errs []error
	for _, d := range owned {
		if err := os.Remove(filepath.Join(m.dir, d)); err != nil && !os.IsNotExist(err) {
			errs = append(errs, err)
		}
	}
	m.active = nil
	if len(errs) > 0 {
		return fmt.Errorf("remove resolver files: %v", errs)
	}
	return nil
}

// ownedLocked lists the files in dir that start with Marker.
func (m *Manager) ownedLocked() ([]string, error) {
	entries, err := os.ReadDir(m.dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read %s: %w", m.dir, err)
	}
	var owned []string
	for _, e := range entries {
		if !e.Type().IsRegular() {
			continue
		}
		if isOwned(filepath.Join(m.dir, e.Name())) {
			owned = append(owned, e.Name())
		}
	}
	return owned, nil
}

func isOwned(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	line, _ := bufio.NewReader(f).ReadString('\n')
	return strings.TrimRight(line, "\r\n") == Marker
}

// writeLocked writes one resolver file atomically (temp file, then rename).
func (m *Manager) writeLocked(domain string) error {
	if err := os.MkdirAll(m.dir, 0o755); err != nil {
		return fmt.Errorf("create %s: %w", m.dir, err)
	}
	content := fmt.Sprintf("%s\nnameserver %s\nport %d\n", Marker, m.nameserver, m.port)

	tmp, err := os.CreateTemp(m.dir, ".routewise-*")
	if err != nil {
		return fmt.Errorf("create resolver file for %s: %w", domain, err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)

	if _, err := tmp.WriteString(content); err != nil {
		tmp.Close()
		return fmt.Errorf("write resolver file for %s: %w", domain, err)
	}
	if err := tmp.Chmod(0o644); err != nil {
		tmp.Close()
		return fmt.Errorf("chmod resolver file for %s: %w", domain, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close resolver file for %s: %w", domain, err)
	}
	if err := os.Rename(tmpPath, filepath.Join(m.dir, domain)); err != nil {
		return fmt.Errorf("install resolver file for %s: %w", domain, err)
	}
	return nil
}

func sortedKeys(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}
