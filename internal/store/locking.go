package store

import "sync"

// lockPair documents the lock ordering used by repository adapters.
type lockPair struct{ mu sync.RWMutex }
