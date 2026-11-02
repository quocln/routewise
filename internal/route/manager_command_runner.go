package route

// SetCommandRunner replaces how the manager runs route and netstat. Only
// tests outside this package use it, so they can drive route mutations
// without touching the real routing table.
func (m *Manager) SetCommandRunner(r CommandRunner) {
	m.SetTable(newCommandTable(r))
}

// CommandRunner returns the runner behind the manager's table, or nil when the
// table is not command-driven. Tests use it to wrap the runner in place.
func (m *Manager) CommandRunner() CommandRunner {
	if t, ok := m.Table().(*commandTable); ok {
		return t.runner
	}
	return nil
}
