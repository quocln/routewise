package route

// batchTable is implemented by a Table whose every route change reads the
// whole route table first (Windows): inside a batch it reads once.
type batchTable interface {
	BeginBatch()
	EndBatch()
}

// BeginRouteBatch lets the route changes that follow, up to the returned
// function, share one read of the system's route table where the platform's
// table needs a read per change. Elsewhere it does nothing. A DNS answer that
// routes several addresses brackets them with it.
func (m *Manager) BeginRouteBatch() (end func()) {
	if b, ok := m.table.(batchTable); ok {
		b.BeginBatch()
		return b.EndBatch
	}
	return func() {}
}
