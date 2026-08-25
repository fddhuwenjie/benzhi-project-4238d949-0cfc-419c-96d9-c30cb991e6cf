package casepkg

// IsTerminal reports whether an incident has reached an immutable terminal state.
func (i *EnvironmentIncident) IsTerminal() bool { return i != nil && i.Status == StatusClosed }

// CanVerify centralizes the state-machine guard for recovery verification.
func (i *EnvironmentIncident) CanVerify() bool {
	if i == nil || i.IsTerminal() {
		return false
	}
	return i.Status == StatusInProgress || i.Status == StatusVerifying || i.Status == StatusReopened || i.Status == StatusAssessed
}
