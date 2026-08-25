package store

import (
	"encoding/json"
	casepkg "envresponse/internal/case"
	"os"
	"path/filepath"
	"sync"
)

type Repository interface {
	Create(*casepkg.EnvironmentIncident) error
	Get(string) (*casepkg.EnvironmentIncident, error)
	Save(*casepkg.EnvironmentIncident, int) error
	List() ([]*casepkg.EnvironmentIncident, error)
	FindByFingerprint(string) (*casepkg.EnvironmentIncident, error)
	BindIdempotency(string, string, string) error
	Idempotency(string) (string, string, bool)
}
type Memory struct {
	mu           sync.RWMutex
	data         map[string]*casepkg.EnvironmentIncident
	fingerprints map[string]string
	idempotency  map[string]struct{ ID, Fingerprint string }
	dir          string
}

func New(dir string) *Memory {
	return &Memory{data: map[string]*casepkg.EnvironmentIncident{}, fingerprints: map[string]string{}, idempotency: map[string]struct{ ID, Fingerprint string }{}, dir: dir}
}
func clone(i *casepkg.EnvironmentIncident) *casepkg.EnvironmentIncident {
	b, _ := json.Marshal(i)
	var c casepkg.EnvironmentIncident
	_ = json.Unmarshal(b, &c)
	return &c
}
func (m *Memory) Create(i *casepkg.EnvironmentIncident) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.data[i.ID]; ok {
		return casepkg.ErrConflict
	}
	m.data[i.ID] = clone(i)
	if i.Fingerprint != "" {
		m.fingerprints[i.Fingerprint] = i.ID
	}
	return m.persist(i)
}
func (m *Memory) FindByFingerprint(fp string) (*casepkg.EnvironmentIncident, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	id := m.fingerprints[fp]
	if id == "" {
		return nil, casepkg.ErrNotFound
	}
	i := m.data[id]
	if i == nil {
		return nil, casepkg.ErrNotFound
	}
	return clone(i), nil
}
func (m *Memory) BindIdempotency(key, id, fp string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if x, ok := m.idempotency[key]; ok {
		if x.ID == id && x.Fingerprint == fp {
			return nil
		}
		return casepkg.ErrConflict
	}
	m.idempotency[key] = struct{ ID, Fingerprint string }{id, fp}
	return nil
}
func (m *Memory) Idempotency(key string) (string, string, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	x, ok := m.idempotency[key]
	return x.ID, x.Fingerprint, ok
}
func (m *Memory) Get(id string) (*casepkg.EnvironmentIncident, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	i, ok := m.data[id]
	if !ok {
		return nil, casepkg.ErrNotFound
	}
	return clone(i), nil
}
func (m *Memory) Save(i *casepkg.EnvironmentIncident, expected int) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	old, ok := m.data[i.ID]
	if !ok {
		return casepkg.ErrNotFound
	}
	if old.Revision != expected {
		return casepkg.ErrConflict
	}
	m.data[i.ID] = clone(i)
	return m.persist(i)
}
func (m *Memory) List() ([]*casepkg.EnvironmentIncident, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]*casepkg.EnvironmentIncident, 0, len(m.data))
	for _, i := range m.data {
		out = append(out, clone(i))
	}
	return out, nil
}
func (m *Memory) persist(i *casepkg.EnvironmentIncident) error {
	if m.dir == "" {
		return nil
	}
	if err := os.MkdirAll(m.dir, 0755); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(i, "", "  ")
	tmp := filepath.Join(m.dir, i.ID+".tmp")
	if err := os.WriteFile(tmp, b, 0644); err != nil {
		return err
	}
	if err := os.Rename(tmp, filepath.Join(m.dir, i.ID+".json")); err != nil {
		return err
	}
	lf, err := os.OpenFile(filepath.Join(m.dir, "events.jsonl"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return err
	}
	defer lf.Close()
	line, _ := json.Marshal(map[string]any{"incident_id": i.ID, "revision": i.Revision, "timeline": i.Timeline})
	_, err = lf.Write(append(line, '\n'))
	return err
}
