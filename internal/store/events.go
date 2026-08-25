package store

import "time"

// EventRecord is the append-only envelope used by replay tooling.
type EventRecord struct {
	IncidentID string    `json:"incident_id"`
	Revision   int       `json:"revision"`
	At         time.Time `json:"at"`
}
