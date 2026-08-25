package casepkg

// ValidStatus is the set of externally visible incident states.
func ValidStatus(s IncidentStatus) bool {
	switch s {
	case "", StatusNew, StatusAssessed, StatusInProgress, StatusVerifying, StatusClosed, StatusReopened:
		return true
	default:
		return false
	}
}
