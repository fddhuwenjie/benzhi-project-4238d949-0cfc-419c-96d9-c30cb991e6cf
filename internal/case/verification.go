package casepkg

import "time"

// VerificationWindowValid validates a bounded observation window.
func VerificationWindowValid(start, end time.Time) bool {
	return start.IsZero() || end.IsZero() || (!end.Before(start) && end.Sub(start) <= 24*time.Hour)
}

// LatestVerification returns the most recently reviewed record.
func (i *EnvironmentIncident) LatestVerification() *VerificationRecord {
	if i == nil || len(i.Verifications) == 0 {
		return nil
	}
	v := i.Verifications[len(i.Verifications)-1]
	return &v
}
