package workflow

import "time"

// Deadline returns a bounded task deadline from a request duration.
func Deadline(now time.Time, minutes int) time.Time {
	if minutes <= 0 {
		minutes = 60
	}
	if minutes > 7*24*60 {
		minutes = 7 * 24 * 60
	}
	return now.Add(time.Duration(minutes) * time.Minute)
}
