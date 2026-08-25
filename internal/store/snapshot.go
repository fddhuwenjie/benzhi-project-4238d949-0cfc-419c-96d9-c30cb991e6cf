package store

import (
	"encoding/json"
	casepkg "envresponse/internal/case"
)

// EncodeSnapshot provides a stable JSON representation for persistence adapters.
func EncodeSnapshot(i *casepkg.EnvironmentIncident) ([]byte, error) { return json.Marshal(i) }
