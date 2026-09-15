// Package history stores a bounded, private decision journal. It is diagnostic
// history, not a source of authorization or a tamper-evident audit trail.
package history

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode"
)

const MaxFileBytes = 8 << 20

type Policy struct {
	RetentionDays int `json:"retentionDays"`
	MaxEvents     int `json:"maxEvents"`
}

func (p Policy) Validated() Policy {
	switch p.RetentionDays {
	case 1, 7, 30:
	default:
		p.RetentionDays = 7
	}
	switch p.MaxEvents {
	case 250, 1000, 5000:
	default:
		p.MaxEvents = 1000
	}
	return p
}

type Event struct {
	ID              uint64     `json:"id"`
	Time            time.Time  `json:"time"`
	Kind            string     `json:"kind"`
	Outcome         string     `json:"outcome"`
	Source          string     `json:"source,omitempty"`
	KeyFingerprint  string     `json:"keyFingerprint,omitempty"`
	HostFingerprint string     `json:"hostFingerprint,omitempty"`
	User            string     `json:"user,omitempty"`
	Scope           string     `json:"scope,omitempty"`
	ExpiresAt       *time.Time `json:"expiresAt,omitempty"`
	// Process names the program a timed decision was tied to, with the PID
	// and PID version of the run it belonged to. They say which program held
	// a decision, long after that program has gone.
	Process        string `json:"process,omitempty"`
	ProcessPID     int32  `json:"processPid,omitempty"`
	ProcessVersion uint32 `json:"processVersion,omitempty"`
}
type Document struct {
	Version int     `json:"version"`
	Events  []Event `json:"events"`
}
type Store struct {
	mu     sync.Mutex
	dir    string
	now    func() time.Time
	loaded bool
	events []Event
	next   uint64
}

func New(dir string, now func() time.Time) *Store {
	if now == nil {
		now = time.Now
	}
	return &Store{dir: dir, now: now}
}
func DefaultDir(home string) string {
	return filepath.Join(home, "Library", "Application Support", "SSH Key Control")
}
func readPrivate(path string, limit int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("history file must be private and regular")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !os.SameFile(info, opened) {
		return nil, errors.New("history file changed while opening")
	}
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, errors.New("history file too large")
	}
	return b, nil
}
func (s *Store) policy() Policy {
	b, err := readPrivate(filepath.Join(s.dir, "history-settings.json"), 8192)
	var p Policy
	if err == nil {
		_ = json.Unmarshal(b, &p)
	}
	return p.Validated()
}
func (s *Store) Record(event Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.MkdirAll(s.dir, 0700); err != nil {
		return err
	}
	info, err := os.Lstat(s.dir)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("history directory must not be a symlink")
	}
	if err := os.Chmod(s.dir, 0700); err != nil {
		return err
	}
	if !s.loaded {
		b, err := readPrivate(filepath.Join(s.dir, "history.json"), MaxFileBytes)
		if err != nil && !os.IsNotExist(err) {
			return err
		}
		if err == nil {
			var doc Document
			if err := json.Unmarshal(b, &doc); err != nil || doc.Version != 1 {
				return errors.New("invalid history document")
			}
			s.events = doc.Events
			for _, e := range s.events {
				if e.ID > s.next {
					s.next = e.ID
				}
			}
		}
		s.loaded = true
	}
	policy := s.policy()
	now := s.now()
	cutoff := now.Add(-time.Duration(policy.RetentionDays) * 24 * time.Hour)
	kept := s.events[:0]
	for _, e := range s.events {
		if !e.Time.Before(cutoff) {
			kept = append(kept, e)
		}
	}
	s.next++
	event.ID = s.next
	event.Time = now.UTC()
	event.User = boundedLabel(event.User)
	event.Process = boundedLabel(event.Process)
	s.events = append(kept, event)
	if len(s.events) > policy.MaxEvents {
		s.events = append([]Event(nil), s.events[len(s.events)-policy.MaxEvents:]...)
	}
	b, err := json.Marshal(Document{Version: 1, Events: s.events})
	if err != nil {
		return err
	}
	if len(b) > MaxFileBytes {
		return errors.New("history exceeds storage limit")
	}
	f, err := os.CreateTemp(s.dir, ".history-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = os.Rename(f.Name(), filepath.Join(s.dir, "history.json")); err != nil {
		return fmt.Errorf("saving history: %w", err)
	}
	return nil
}
func boundedLabel(s string) string {
	runes := []rune(strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.In(r, unicode.Cf) {
			return ' '
		}
		return r
	}, s))
	if len(runes) > 128 {
		runes = runes[:128]
	}
	return string(runes)
}
