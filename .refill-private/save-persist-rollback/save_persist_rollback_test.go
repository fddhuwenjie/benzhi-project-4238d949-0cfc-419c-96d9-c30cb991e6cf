package savepersistrollback

import (
	"encoding/json"
	casepkg "envresponse/internal/case"
	"envresponse/internal/store"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSaveFailureDoesNotMutateMemory(t *testing.T) {
	dir := t.TempDir()
	repo := store.New(dir)
	original := &casepkg.EnvironmentIncident{
		ID:          "incident-rollback",
		VenueID:     "venue-a",
		Zone:        "zone-a",
		Metric:      "temperature",
		ObservedAt:  time.Now().UTC(),
		Status:      casepkg.StatusAssessed,
		Revision:    1,
		Fingerprint: "old-fingerprint",
		Tasks:       map[string]*casepkg.ResponseTask{},
	}
	if err := repo.Create(original); err != nil {
		t.Fatalf("create baseline: %v", err)
	}

	// 运行中资源失效：事件日志路径被替换为目录。persist 会先替换快照，
	// 然后在打开日志时失败，形成磁盘快照与内存状态的双重半提交。
	logPath := filepath.Join(dir, "events.jsonl")
	if err := os.Remove(logPath); err != nil {
		t.Fatalf("remove event log: %v", err)
	}
	if err := os.Mkdir(logPath, 0700); err != nil {
		t.Fatalf("replace event log: %v", err)
	}

	updated := *original
	updated.Status = casepkg.StatusInProgress
	updated.Revision = 2
	updated.Fingerprint = "new-fingerprint"
	if err := repo.Save(&updated, 1); err == nil {
		t.Fatal("expected persistence failure")
	}

	got, err := repo.Get(original.ID)
	if err != nil {
		t.Fatalf("get after failed save: %v", err)
	}
	if got.Status != original.Status || got.Revision != original.Revision {
		t.Fatalf("failed save leaked into memory: status=%s revision=%d", got.Status, got.Revision)
	}
	data, err := os.ReadFile(filepath.Join(dir, original.ID+".json"))
	if err != nil {
		t.Fatalf("read snapshot after failed save: %v", err)
	}
	var disk casepkg.EnvironmentIncident
	if err := json.Unmarshal(data, &disk); err != nil {
		t.Fatalf("decode snapshot after failed save: %v", err)
	}
	if disk.Status != original.Status || disk.Revision != original.Revision {
		t.Fatalf("failed save replaced snapshot before returning error: status=%s revision=%d", disk.Status, disk.Revision)
	}
	if leaked, err := repo.FindByFingerprint(updated.Fingerprint); err == nil || leaked != nil {
		t.Fatalf("failed save leaked fingerprint index")
	}
}
