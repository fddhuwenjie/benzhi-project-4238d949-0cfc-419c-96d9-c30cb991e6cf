package rules

// SupportedMetrics returns the metrics accepted by the domain rules.
func SupportedMetrics() []string { return []string{"humidity", "temperature", "light"} }
