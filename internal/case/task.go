package casepkg

// PendingTasks returns task identifiers that still need action.
func (i *EnvironmentIncident) PendingTasks() []string {
	if i == nil {
		return nil
	}
	out := make([]string, 0)
	for id, task := range i.Tasks {
		if task != nil && task.Status != "completed" {
			out = append(out, id)
		}
	}
	return out
}

// TaskComplete reports whether a task contains completion evidence.
func (t *ResponseTask) TaskComplete() bool {
	return t != nil && t.Status == "completed" && t.CompletedAt != nil
}
