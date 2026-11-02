package route

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/quocln/routewise/internal/ledger"
)

const (
	// sessionJournalPrefix and sessionJournalSuffix frame the per-tunnel
	// journal name: transition-<interface>.json, next to the base journal.
	sessionJournalPrefix = "transition-"
	sessionJournalSuffix = ".json"

	journalDirMode  os.FileMode = 0700
	journalFileMode os.FileMode = 0600

	// maxJournalBytes bounds how much a corrupt or hostile journal file can
	// make the daemon read into memory before validation rejects it.
	maxJournalBytes = 1 << 20 // 1 MiB

	transactionSchemaVersion = 1
)

// Errors returned by loading an on-disk transition journal. They are typed
// so callers (and tests) can distinguish "nothing to recover" from "the
// journal exists but cannot be trusted."
var (
	ErrJournalSymlink        = errors.New("transition journal path is a symlink")
	ErrJournalNotRegular     = errors.New("transition journal is not a regular file")
	ErrJournalInsecureOwner  = errors.New("transition journal has insecure ownership")
	ErrJournalInsecureMode   = errors.New("transition journal has insecure permissions")
	ErrJournalTooLarge       = errors.New("transition journal exceeds maximum size")
	ErrJournalMalformed      = errors.New("transition journal is malformed")
	ErrJournalUnknownVersion = errors.New("transition journal has unknown schema version")
)

// journalPhase tracks where in the activate/deactivate lifecycle a
// transition currently is, so a process that crashes mid-transition can
// tell recovery what it was doing.
type journalPhase string

const (
	phaseActivating    journalPhase = "activating"
	phaseActive        journalPhase = "active"
	phaseCompensating  journalPhase = "compensating"
	phaseComplete      journalPhase = "complete"
	phaseUnrecoverable journalPhase = "unrecoverable"
)

// journalStepKind identifies which kind of mutation a journalStep records,
// which in turn determines how compensateStepLocked reverses it.
type journalStepKind string

const (
	stepAddRoute      journalStepKind = "add_route"
	stepDeleteRoute   journalStepKind = "delete_route"
	stepChangeDefault journalStepKind = "change_default"
	// stepAddRule is a policy rule that looks up the main table, added ahead of
	// a full tunnel's own rule (Linux only).
	stepAddRule journalStepKind = "add_rule"
)

// journalStep records one completed mutation. Steps are appended in the
// order they were applied and compensated in reverse order.
type journalStep struct {
	Kind journalStepKind `json:"kind"`

	Destination string `json:"destination,omitempty"`
	Gateway     string `json:"gateway,omitempty"`
	Interface   string `json:"interface,omitempty"`

	// Priority is only set for stepAddRule: the priority of the rule added.
	Priority int `json:"priority,omitempty"`

	// PriorGateway is only set for stepChangeDefault: the default gateway in
	// effect immediately before this step, so compensation can restore it.
	PriorGateway string `json:"prior_gateway,omitempty"`
	// PriorInterface is the interface of that default route. When it was a
	// VPN tunnel (a NetworkExtension client's default), compensation points
	// the default back at the tunnel only while the tunnel still exists.
	PriorInterface string `json:"prior_interface,omitempty"`

	// Existed reports whether the route already existed before RouteWise
	// touched it. For stepAddRoute, false means compensation should delete
	// it; true means it predates RouteWise and must be left alone. For
	// stepDeleteRoute it is always true: RouteWise only ever deletes routes
	// it found already present and owned.
	Existed bool `json:"existed"`
}

// routeSnapshot is a point-in-time record of one route RouteWise is about to
// touch, kept for audit independent of the step log used for compensation.
type routeSnapshot struct {
	Destination string `json:"destination"`
	Gateway     string `json:"gateway,omitempty"`
	Interface   string `json:"interface,omitempty"`
	Flags       string `json:"flags,omitempty"`
	Existed     bool   `json:"existed"`
}

// transaction is the on-disk shape of the transition journal.
type transaction struct {
	SchemaVersion int             `json:"schema_version"`
	GenerationID  string          `json:"generation_id"`
	Phase         journalPhase    `json:"phase"`
	PreState      []routeSnapshot `json:"pre_state"`
	Steps         []journalStep   `json:"steps"`
	CreatedAt     time.Time       `json:"created_at"`
	UpdatedAt     time.Time       `json:"updated_at"`
	FailureReason string          `json:"failure_reason,omitempty"`
}

// defaultGenerationID produces a value unique enough to tell one activation
// attempt's journal apart from another's in logs; it carries no security
// meaning by itself.
func defaultGenerationID() string {
	return fmt.Sprintf("%d-%d", time.Now().UnixNano(), os.Getpid())
}

// transactionStore persists the transition journal with fsync+rename
// durability and validates it on load. The before* hooks let tests fail
// deterministically at each durability boundary (before the write, before
// fsync, before rename, before the directory fsync) without touching a real
// filesystem fault injector.
type transactionStore struct {
	path string

	beforeWrite   func() error
	beforeSync    func() error
	beforeRename  func() error
	beforeDirSync func() error
}

// checkJournalOwnership rejects a uid other than root or the process's own
// effective uid. Allowing the current euid (not only root) matches the
// production invariant exactly when the daemon runs as root, as it always
// does, while letting this package's own tests exercise the same code path
// unprivileged.
func checkJournalOwnership(uid uint32) error {
	if uid != 0 && uint64(uid) != uint64(os.Geteuid()) {
		return fmt.Errorf("%w: uid %d", ErrJournalInsecureOwner, uid)
	}
	return nil
}

// checkJournalMode rejects any group or world access at all; the journal is
// root-owned and mode 0600 only.
func checkJournalMode(perm os.FileMode) error {
	if perm&0077 != 0 {
		return fmt.Errorf("%w: mode %o", ErrJournalInsecureMode, perm)
	}
	return nil
}

// journalFileSecurityCheck is a variable so tests that keep journals in a
// temp directory, which no machine-wide ACL protects, can stand in for the
// per-OS check.
var journalFileSecurityCheck = checkJournalFileSecurity

// load reads and validates the journal. ok is false with a nil error when no
// journal file exists, which is the common case of a clean startup.
func (s *transactionStore) load() (tx *transaction, ok bool, err error) {
	info, err := os.Lstat(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("stat transition journal: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, false, fmt.Errorf("%w: %s", ErrJournalSymlink, s.path)
	}
	if !info.Mode().IsRegular() {
		return nil, false, fmt.Errorf("%w: %s", ErrJournalNotRegular, s.path)
	}
	if info.Size() > maxJournalBytes {
		return nil, false, fmt.Errorf("%w: %d bytes", ErrJournalTooLarge, info.Size())
	}
	if err := journalFileSecurityCheck(s.path, info); err != nil {
		return nil, false, err
	}

	data, err := os.ReadFile(s.path)
	if err != nil {
		return nil, false, fmt.Errorf("read transition journal: %w", err)
	}
	if len(data) > maxJournalBytes {
		return nil, false, fmt.Errorf("%w: %d bytes", ErrJournalTooLarge, len(data))
	}

	var parsed transaction
	if err := json.Unmarshal(data, &parsed); err != nil {
		return nil, false, fmt.Errorf("%w: %v", ErrJournalMalformed, err)
	}
	if parsed.SchemaVersion != transactionSchemaVersion {
		return nil, false, fmt.Errorf("%w: %d", ErrJournalUnknownVersion, parsed.SchemaVersion)
	}
	return &parsed, true, nil
}

// save writes tx atomically: temp file in the journal directory, chmod
// 0600, write, fsync, close, rename over the target, then fsync the
// directory so the rename itself survives a crash.
func (s *transactionStore) save(tx *transaction) error {
	if s.beforeWrite != nil {
		if err := s.beforeWrite(); err != nil {
			return err
		}
	}

	tx.UpdatedAt = time.Now().UTC()
	data, err := json.Marshal(tx)
	if err != nil {
		return fmt.Errorf("marshal transition journal: %w", err)
	}
	err = ledger.WriteAtomic(s.path, data, ledger.WriteOptions{
		Durable:       true,
		SyncDir:       syncJournalDir,
		BeforeSync:    s.beforeSync,
		BeforeRename:  s.beforeRename,
		BeforeDirSync: s.beforeDirSync,
	})
	if err != nil {
		return fmt.Errorf("write transition journal: %w", err)
	}
	return nil
}

// remove deletes the journal file. A missing file is not an error: it means
// the transition already concluded.
func (s *transactionStore) remove() error {
	err := os.Remove(s.path)
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

// SessionJournalPath is where the manager for one tunnel keeps its transition
// journal: transition-<iface>.json in the base journal's directory. The
// interface name is validated, so it can never escape that directory.
func SessionJournalPath(baseJournalPath, iface string) (string, error) {
	if err := ValidateInterfaceName(iface); err != nil {
		return "", fmt.Errorf("session journal: %w", err)
	}
	token := iface
	if runtime.GOOS == "windows" {
		token = encodeJournalToken(iface)
	}
	return filepath.Join(filepath.Dir(baseJournalPath), sessionJournalPrefix+token+sessionJournalSuffix), nil
}

// encodeJournalToken leaves a name made of letters, digits, '_' and '-' as it
// is and hex-encodes any other, behind a '~' no plain name contains. Windows
// aliases may hold characters a file name cannot ('*', '?', '<') or that
// NTFS reads as a stream (':'), and its trailing dots and spaces are dropped.
func encodeJournalToken(iface string) string {
	plain := iface != ""
	for _, r := range iface {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-') {
			plain = false
			break
		}
	}
	if plain {
		return iface
	}
	return "~" + hex.EncodeToString([]byte(iface))
}

// decodeJournalToken reverses encodeJournalToken.
func decodeJournalToken(token string) (string, bool) {
	hexed, ok := strings.CutPrefix(token, "~")
	if !ok {
		return token, true
	}
	raw, err := hex.DecodeString(hexed)
	if err != nil || len(raw) == 0 {
		return "", false
	}
	return string(raw), true
}

// SessionJournalPaths lists the per-tunnel journals sitting next to the base
// journal, which a previous process left behind. Names that are not a valid
// interface are ignored. The newest journal comes first: recovery undoes
// activations in the reverse of the order they happened, whatever order the
// directory lists them in. A journal whose time cannot be read sorts last, and
// ties break by path, so the order is the same on every run.
func SessionJournalPaths(baseJournalPath string) ([]string, error) {
	dir := filepath.Dir(baseJournalPath)
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("list session journals: %w", err)
	}
	var out []string
	for _, e := range entries {
		name := e.Name()
		if !strings.HasPrefix(name, sessionJournalPrefix) || !strings.HasSuffix(name, sessionJournalSuffix) {
			continue
		}
		token := strings.TrimSuffix(strings.TrimPrefix(name, sessionJournalPrefix), sessionJournalSuffix)
		iface, ok := decodeJournalToken(token)
		if !ok || ValidateInterfaceName(iface) != nil {
			continue
		}
		out = append(out, filepath.Join(dir, name))
	}
	created := make(map[string]time.Time, len(out))
	for _, path := range out {
		created[path] = journalCreatedAt(path)
	}
	slices.SortFunc(out, func(a, b string) int {
		if c := created[b].Compare(created[a]); c != 0 {
			return c
		}
		return strings.Compare(a, b)
	})
	return out, nil
}

// journalCreatedAt reads when a journal's activation began, or the zero time
// when the file cannot be read. Only ordering depends on it; trust in the
// journal's contents is decided later by load.
func journalCreatedAt(path string) time.Time {
	f, err := os.Open(path)
	if err != nil {
		return time.Time{}
	}
	defer f.Close()
	var head struct {
		CreatedAt time.Time `json:"created_at"`
	}
	if err := json.NewDecoder(io.LimitReader(f, maxJournalBytes)).Decode(&head); err != nil {
		return time.Time{}
	}
	return head.CreatedAt
}
