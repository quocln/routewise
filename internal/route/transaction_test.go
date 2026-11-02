package route

import (
	"errors"
	"github.com/quocln/routewise/internal/testenv"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func sampleTransaction() *transaction {
	return &transaction{
		SchemaVersion: transactionSchemaVersion,
		GenerationID:  "gen-1",
		Phase:         phaseActivating,
		PreState: []routeSnapshot{
			{Destination: "default", Gateway: "192.168.1.1", Existed: true},
		},
		Steps: []journalStep{
			{Kind: stepChangeDefault, Gateway: "10.8.0.1", PriorGateway: "192.168.1.1"},
		},
		CreatedAt: time.Now().UTC(),
	}
}

func TestTransactionStoreSaveLoadRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "transition.json")
	s := &transactionStore{path: path}

	tx := sampleTransaction()
	if err := s.save(tx); err != nil {
		t.Fatalf("save: %v", err)
	}

	loaded, ok, err := s.load()
	if err != nil || !ok {
		t.Fatalf("load: ok=%v err=%v", ok, err)
	}
	if loaded.GenerationID != tx.GenerationID || loaded.Phase != tx.Phase {
		t.Errorf("loaded transaction mismatch: %+v", loaded)
	}
	if len(loaded.Steps) != 1 || loaded.Steps[0].Gateway != "10.8.0.1" {
		t.Errorf("loaded steps mismatch: %+v", loaded.Steps)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat journal: %v", err)
	}
	if !testenv.HasPerm(info, journalFileMode) {
		t.Errorf("journal mode = %o, want %o", info.Mode().Perm(), journalFileMode)
	}

	dirInfo, err := os.Stat(filepath.Dir(path))
	if err != nil {
		t.Fatalf("stat journal dir: %v", err)
	}
	if !testenv.HasPerm(dirInfo, journalDirMode) {
		t.Errorf("journal dir mode = %o, want %o", dirInfo.Mode().Perm(), journalDirMode)
	}
}

func TestTransactionStoreLoadMissingIsNotAnError(t *testing.T) {
	s := &transactionStore{path: filepath.Join(t.TempDir(), "transition.json")}

	tx, ok, err := s.load()
	if err != nil {
		t.Fatalf("expected no error for missing journal, got %v", err)
	}
	if ok || tx != nil {
		t.Errorf("expected ok=false, tx=nil for missing journal, got ok=%v tx=%+v", ok, tx)
	}
}

func TestTransactionStoreRemoveIsIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "transition.json")
	s := &transactionStore{path: path}

	if err := s.save(sampleTransaction()); err != nil {
		t.Fatalf("save: %v", err)
	}
	if err := s.remove(); err != nil {
		t.Fatalf("first remove: %v", err)
	}
	if err := s.remove(); err != nil {
		t.Fatalf("second remove should be a no-op, got %v", err)
	}
}

func TestTransactionStoreLoadRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real.json")
	if err := os.WriteFile(real, []byte("{}"), journalFileMode); err != nil {
		t.Fatalf("write real: %v", err)
	}
	link := filepath.Join(dir, "transition.json")
	if err := os.Symlink(real, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	s := &transactionStore{path: link}
	_, _, err := s.load()
	if !errors.Is(err, ErrJournalSymlink) {
		t.Errorf("expected ErrJournalSymlink, got %v", err)
	}
}

func TestTransactionStoreLoadRejectsInsecureMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows has no mode bits; the access list check has its own test")
	}
	path := filepath.Join(t.TempDir(), "transition.json")
	if err := os.WriteFile(path, []byte("{}"), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	s := &transactionStore{path: path}
	_, _, err := s.load()
	if !errors.Is(err, ErrJournalInsecureMode) {
		t.Errorf("expected ErrJournalInsecureMode, got %v", err)
	}
}

func TestTransactionStoreLoadRejectsOversized(t *testing.T) {
	path := filepath.Join(t.TempDir(), "transition.json")
	oversized := make([]byte, maxJournalBytes+1)
	for i := range oversized {
		oversized[i] = ' '
	}
	if err := os.WriteFile(path, oversized, journalFileMode); err != nil {
		t.Fatalf("write: %v", err)
	}

	s := &transactionStore{path: path}
	_, _, err := s.load()
	if !errors.Is(err, ErrJournalTooLarge) {
		t.Errorf("expected ErrJournalTooLarge, got %v", err)
	}
}

func TestTransactionStoreLoadRejectsMalformedJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "transition.json")
	if err := os.WriteFile(path, []byte("{not json"), journalFileMode); err != nil {
		t.Fatalf("write: %v", err)
	}

	s := &transactionStore{path: path}
	_, _, err := s.load()
	if !errors.Is(err, ErrJournalMalformed) {
		t.Errorf("expected ErrJournalMalformed, got %v", err)
	}
}

func TestTransactionStoreLoadRejectsUnknownSchemaVersion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "transition.json")
	if err := os.WriteFile(path, []byte(`{"schema_version":99}`), journalFileMode); err != nil {
		t.Fatalf("write: %v", err)
	}

	s := &transactionStore{path: path}
	_, _, err := s.load()
	if !errors.Is(err, ErrJournalUnknownVersion) {
		t.Errorf("expected ErrJournalUnknownVersion, got %v", err)
	}
}

func TestTransactionStoreLoadRejectsNonRegular(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "transition.json")
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	s := &transactionStore{path: path}
	_, _, err := s.load()
	if !errors.Is(err, ErrJournalNotRegular) {
		t.Errorf("expected ErrJournalNotRegular, got %v", err)
	}
}

func TestCheckJournalOwnership(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows has no uid; journal_security_windows_test.go covers its owner rule")
	}
	if err := checkJournalOwnership(0); err != nil {
		t.Errorf("uid 0 (root) should always be accepted, got %v", err)
	}
	if err := checkJournalOwnership(uint32(os.Geteuid())); err != nil {
		t.Errorf("the test process's own euid should be accepted, got %v", err)
	}
	if err := checkJournalOwnership(65534); err == nil {
		t.Error("expected an unrelated uid to be rejected")
	} else if !errors.Is(err, ErrJournalInsecureOwner) {
		t.Errorf("expected ErrJournalInsecureOwner, got %v", err)
	}
}

func TestCheckJournalMode(t *testing.T) {
	if err := checkJournalMode(0600); err != nil {
		t.Errorf("mode 0600 should be accepted, got %v", err)
	}
	for _, perm := range []os.FileMode{0640, 0604, 0660, 0666, 0777} {
		if err := checkJournalMode(perm); err == nil {
			t.Errorf("mode %o should be rejected", perm)
		} else if !errors.Is(err, ErrJournalInsecureMode) {
			t.Errorf("mode %o: expected ErrJournalInsecureMode, got %v", perm, err)
		}
	}
}

// --- Durability boundary fault injection ---

func TestTransactionStoreSaveFailsBeforeWriteLeavesNoJournal(t *testing.T) {
	path := filepath.Join(t.TempDir(), "transition.json")
	injected := errors.New("injected: before write")
	s := &transactionStore{path: path, beforeWrite: func() error { return injected }}

	if err := s.save(sampleTransaction()); !errors.Is(err, injected) {
		t.Fatalf("expected injected error, got %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("expected no journal file to exist, stat err=%v", err)
	}
}

func TestTransactionStoreSaveFailsBeforeSyncLeavesPriorJournalIntact(t *testing.T) {
	path := filepath.Join(t.TempDir(), "transition.json")
	s := &transactionStore{path: path}

	first := sampleTransaction()
	if err := s.save(first); err != nil {
		t.Fatalf("seed save: %v", err)
	}

	injected := errors.New("injected: before sync")
	s.beforeSync = func() error { return injected }

	second := sampleTransaction()
	second.GenerationID = "replacement-gen"
	if err := s.save(second); !errors.Is(err, injected) {
		t.Fatalf("expected injected error, got %v", err)
	}

	loaded, ok, err := s.load()
	if err != nil || !ok {
		t.Fatalf("expected prior journal to survive a beforeSync failure, ok=%v err=%v", ok, err)
	}
	if loaded.GenerationID != first.GenerationID {
		t.Errorf("expected the original journal content to survive, got generation %q", loaded.GenerationID)
	}
}

func TestTransactionStoreSaveFailsBeforeRenameLeavesPriorJournalIntact(t *testing.T) {
	path := filepath.Join(t.TempDir(), "transition.json")
	s := &transactionStore{path: path}

	if err := s.save(sampleTransaction()); err != nil {
		t.Fatalf("seed save: %v", err)
	}

	injected := errors.New("injected: before rename")
	s.beforeRename = func() error { return injected }

	second := sampleTransaction()
	second.GenerationID = "replacement-gen"
	if err := s.save(second); !errors.Is(err, injected) {
		t.Fatalf("expected injected error, got %v", err)
	}

	loaded, ok, err := s.load()
	if err != nil || !ok {
		t.Fatalf("expected prior journal to survive a beforeRename failure, ok=%v err=%v", ok, err)
	}
	if loaded.GenerationID != sampleTransaction().GenerationID {
		t.Errorf("expected the original journal content to survive rename failure, got generation %q", loaded.GenerationID)
	}

	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatalf("read journal dir: %v", err)
	}
	for _, e := range entries {
		if e.Name() != filepath.Base(path) {
			t.Errorf("expected temp file to be cleaned up, found leftover %q", e.Name())
		}
	}
}

func TestTransactionStoreSaveFailsAfterRenameBeforeDirSyncStillCommitsData(t *testing.T) {
	path := filepath.Join(t.TempDir(), "transition.json")
	injected := errors.New("injected: before dir sync")
	s := &transactionStore{path: path, beforeDirSync: func() error { return injected }}

	tx := sampleTransaction()
	err := s.save(tx)
	if !errors.Is(err, injected) {
		t.Fatalf("expected injected error, got %v", err)
	}

	// The rename already happened by this point, so despite save() reporting
	// an error (the directory fsync itself failed), the journal content is
	// present on disk. A subsequent process retrying save (or load) sees a
	// consistent file; only the durability guarantee for that last fsync is
	// what failed, not the data.
	loaded, ok, loadErr := s.load()
	if loadErr != nil || !ok {
		t.Fatalf("expected renamed journal to be readable despite dir-sync failure, ok=%v err=%v", ok, loadErr)
	}
	if loaded.GenerationID != tx.GenerationID {
		t.Errorf("loaded journal mismatch: %+v", loaded)
	}
}
