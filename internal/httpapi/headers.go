package httpapi

import "net/http"

// RequestID returns the idempotency token used by mutating endpoints.
func RequestID(r *http.Request) string {
	if r == nil {
		return ""
	}
	return r.Header.Get("Idempotency-Key")
}
