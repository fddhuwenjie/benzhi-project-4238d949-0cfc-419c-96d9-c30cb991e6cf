package casepkg

import "errors"

var (
	ErrNotFound = errors.New("not found")
	ErrConflict = errors.New("revision conflict")
	ErrInvalid  = errors.New("invalid state")
	ErrStorage  = errors.New("storage error")
)
