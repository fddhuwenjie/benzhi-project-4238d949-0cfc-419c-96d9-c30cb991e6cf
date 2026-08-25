package rules

import "time"

// WindowDuration clamps caller-provided windows to a safe bounded interval.
func WindowDuration(d, fallback time.Duration) time.Duration {
	if d <= 0 {
		d = fallback
	}
	if d > 24*time.Hour {
		return 24 * time.Hour
	}
	return d
}
