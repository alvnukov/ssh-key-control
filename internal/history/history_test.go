package history

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func readDoc(t *testing.T, dir string) Document {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, "history.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc Document
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	return doc
}
func TestPrivateBoundedHistorySurvivesRestart(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "history")
	now := time.Date(2026, 9, 12, 10, 0, 0, 0, time.UTC)
	store := New(dir, func() time.Time { return now })
	if err := store.Record(Event{Kind: "decision", Outcome: "denied", User: "alice\n\u202eserver"}); err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]os.FileMode{dir: 0700, filepath.Join(dir, "history.json"): 0600} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != want {
			t.Fatalf("mode %v != %v", info.Mode().Perm(), want)
		}
	}
	doc := readDoc(t, dir)
	if doc.Events[0].User != "alice  server" {
		t.Fatalf("unsafe display label %q", doc.Events[0].User)
	}
	restarted := New(dir, func() time.Time { return now })
	if err := restarted.Record(Event{Kind: "agent", Outcome: "started"}); err != nil {
		t.Fatal(err)
	}
	doc = readDoc(t, dir)
	if len(doc.Events) != 2 || doc.Events[1].ID != 2 {
		t.Fatal("history lost on restart")
	}
}
func TestRetentionCountAndConcurrentWrites(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 9, 12, 10, 0, 0, 0, time.UTC)
	store := New(dir, func() time.Time { return now })
	if err := store.Record(Event{Kind: "decision"}); err != nil {
		t.Fatal(err)
	}
	now = now.Add(8 * 24 * time.Hour)
	if err := os.WriteFile(filepath.Join(dir, "history-settings.json"), []byte(`{"retentionDays":7,"maxEvents":250}`), 0600); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for range 5 {
		wg.Go(func() {
			for range 55 {
				if err := store.Record(Event{Kind: "decision", Outcome: "denied"}); err != nil {
					t.Error(err)
				}
			}
		})
	}
	wg.Wait()
	doc := readDoc(t, dir)
	if len(doc.Events) != 250 {
		t.Fatalf("count=%d", len(doc.Events))
	}
	for i, e := range doc.Events {
		if !e.Time.Equal(now) {
			t.Fatal("expired event retained")
		}
		if i > 0 && doc.Events[i-1].ID >= e.ID {
			t.Fatal("duplicate or unordered events")
		}
	}
}
func TestUnsafeHistoryPathsFailClosed(t *testing.T) {
	for _, directoryLink := range []bool{false, true} {
		base := t.TempDir()
		target := filepath.Join(base, "target")
		dir := filepath.Join(base, "history")
		if directoryLink {
			if err := os.Mkdir(target, 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, dir); err != nil {
				t.Fatal(err)
			}
		} else {
			if err := os.Mkdir(dir, 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(target, []byte("preserve"), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, filepath.Join(dir, "history.json")); err != nil {
				t.Fatal(err)
			}
		}
		if err := New(dir, nil).Record(Event{}); err == nil {
			t.Fatal("symlink accepted")
		}
		if !directoryLink {
			b, _ := os.ReadFile(target)
			if string(b) != "preserve" {
				t.Fatal("target modified")
			}
		}
	}
}
func TestPolicyValidation(t *testing.T) {
	if got := (Policy{RetentionDays: -1, MaxEvents: 9999999}).Validated(); got != (Policy{7, 1000}) {
		t.Fatal(got)
	}
}
