package concurrentidempotency

import (
	"envresponse/internal/case"
	"envresponse/internal/store"
	"envresponse/internal/workflow"
	"sync"
	"testing"
	"time"
)

// barrierRepo forces both requests past the idempotency/fingerprint read before
// either request can create its aggregate, making the race deterministic.
type barrierRepo struct {
	store.Repository
	mu          sync.Mutex
	reads       int
	release     chan struct{}
	once        sync.Once
	lists       int
	listRelease chan struct{}
	listOnce    sync.Once
}

func (r *barrierRepo) List() ([]*casepkg.EnvironmentIncident, error) {
	r.mu.Lock()
	r.lists++
	n := r.lists
	if r.lists == 2 {
		r.listOnce.Do(func() { close(r.listRelease) })
	}
	r.mu.Unlock()
	<-r.listRelease
	if n > 2 {
		return r.Repository.List()
	}
	return []*casepkg.EnvironmentIncident{}, nil
}

func (r *barrierRepo) FindByFingerprint(fp string) (*casepkg.EnvironmentIncident, error) {
	r.mu.Lock()
	r.reads++
	if r.reads == 2 {
		r.once.Do(func() { close(r.release) })
	}
	r.mu.Unlock()
	<-r.release
	// Both initial reads intentionally observe an empty index. The production
	// code has no atomic check-and-bind operation to close this gap.
	return nil, casepkg.ErrNotFound
}

func TestConcurrentIdempotencySingleCreate(t *testing.T) {
	base := store.New("")
	repo := &barrierRepo{Repository: base, release: make(chan struct{}), listRelease: make(chan struct{})}
	flow := workflow.New(repo)
	now := time.Now().UTC().Add(-time.Minute)
	in := workflow.CreateInput{
		VenueID: "venue-a", Zone: "gallery-1", Metric: "temperature",
		ObservedValue: 30, Threshold: 24, ObservedAt: now,
		Source: "sensor-main", CreatedBy: "operator", Assignee: "operator",
		IdempotencyKey: "idem-concurrent-1",
	}
	type result struct {
		id  string
		err error
	}
	results := make(chan result, 2)
	var wg sync.WaitGroup
	for n := 0; n < 2; n++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			i, _, err := flow.CreateIncident(in)
			if i != nil {
				results <- result{id: i.ID, err: err}
				return
			}
			results <- result{err: err}
		}()
	}
	wg.Wait()
	close(results)

	var successes []result
	for r := range results {
		if r.err == nil {
			successes = append(successes, r)
		}
	}
	if len(successes) != 1 {
		t.Fatalf("TestConcurrentIdempotencySingleCreate: expected one successful create, got %d results", len(successes))
	}
	items, err := repo.List()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("TestConcurrentIdempotencySingleCreate: expected one persisted incident, got %d", len(items))
	}
	got, _, ok := repo.Idempotency(in.IdempotencyKey)
	if !ok || got != successes[0].id {
		t.Fatalf("idempotency binding mismatch: got %q (ok=%v), success=%q", got, ok, successes[0].id)
	}
}
