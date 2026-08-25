package casepkg

// AuditReady indicates that all response tasks are complete and the incident can close.
func (i *EnvironmentIncident) AuditReady() bool {
	return i != nil && i.OpenTasks() == 0 && i.Audit == nil
}
