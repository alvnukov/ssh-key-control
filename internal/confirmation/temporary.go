package confirmation

import (
	"crypto/rand"
	"errors"
	"sort"
	"sync"
	"time"

	"github.com/alvnukov/ssh-key-control/internal/proc"
	"github.com/alvnukov/ssh-key-control/internal/ui"
)

type temporaryDecision struct {
	id, host string
	allowed  bool
	expires  time.Time
	// anchor is the process this decision was granted to, kept so the window
	// can name it and so that revoking one row can find its siblings. A zero
	// anchor belongs to the decisions that were never tied to a program.
	anchor proc.Link
}

// anchorName is what a person would recognize: the executable if the kernel
// still knows it, the short command name otherwise, nothing when the decision
// is not anchored at all.
func (d temporaryDecision) anchorName() string {
	if d.anchor.PID == 0 {
		return ""
	}
	return clean(d.anchor.Display())
}

type decisionStore struct {
	mu    sync.Mutex
	now   func() time.Time
	items map[grantKey]temporaryDecision
}

func newDecisionStore(now func() time.Time) *decisionStore {
	return &decisionStore{now: now, items: make(map[grantKey]temporaryDecision)}
}

func (s *decisionStore) prune() {
	now := s.now()
	for key, item := range s.items {
		if !now.Before(item.expires) {
			delete(s.items, key)
		}
	}
}

func (s *decisionStore) lookup(key grantKey) (temporaryDecision, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.prune()
	// An anchored decision needs no liveness check of its own. Its key holds
	// the fingerprint of a chain of processes, and the caller's key is built
	// by walking live processes upward, so a dead ancestor simply stops being
	// found: the decision expires with the program it was given to.
	item, ok := s.items[key]
	return item, ok
}

func (s *decisionStore) forget(key grantKey) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.items, key)
}

func decisionExpiry(now time.Time, choice ui.Confirmation) (time.Time, error) {
	duration, day, err := choice.Lifetime()
	if err != nil {
		return time.Time{}, err
	}
	if day {
		y, m, d := now.Date()
		return time.Date(y, m, d+1, 0, 0, 0, 0, now.Location()), nil
	}
	if duration > 0 {
		return now.Add(duration), nil
	}
	return time.Time{}, nil
}

func (s *decisionStore) remember(key grantKey, host string, anchor proc.Link, choice ui.Confirmation) (time.Time, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.items, key)
	until, err := decisionExpiry(s.now(), choice)
	if err != nil {
		return time.Time{}, err
	}
	if !until.IsZero() {
		s.items[key] = temporaryDecision{rand.Text(), clean(host), choice.Allowed, until, anchor}
	}
	return until, nil
}

func (a *Authorizer) TemporaryDecisions() []ui.TemporaryDecision {
	s := a.decisions
	s.mu.Lock()
	defer s.mu.Unlock()
	s.prune()
	items := make([]ui.TemporaryDecision, 0, len(s.items))
	for key, item := range s.items {
		row := ui.TemporaryDecision{
			ID: item.id, KeyFingerprint: key.key, HostFingerprint: key.server,
			Host: item.host, User: key.user, Allowed: item.allowed,
			ExpiresAt: item.expires.UTC().Format(time.RFC3339),
		}
		if name := item.anchorName(); name != "" {
			row.Process, row.ProcessPID = name, item.anchor.PID
			row.ProcessLive = proc.Alive(item.anchor)
		}
		items = append(items, row)
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].ExpiresAt == items[j].ExpiresAt {
			return items[i].ID < items[j].ID
		}
		return items[i].ExpiresAt < items[j].ExpiresAt
	})
	return items
}

// ChangeTemporaryDecision is used only by the daemon's own helper pipe;
// the SSH/control socket deliberately exposes no mutation operation.
func (a *Authorizer) ChangeTemporaryDecision(change ui.DecisionChange) error {
	if change.ID == "" || len(change.ID) > 128 {
		return errors.New("select an active temporary decision")
	}
	if change.Action != "revoke" && change.Action != "revoke-process" && change.Action != "update" {
		return errors.New("unknown temporary decision action")
	}
	if change.Action != "update" && (change.Minutes != 0 || change.EndOfDay) {
		return errors.New("revoking a decision cannot specify a duration")
	}
	if change.Action == "update" && ((change.EndOfDay && change.Minutes != 0) ||
		(!change.EndOfDay && (change.Minutes < 1 || change.Minutes > 1440))) {
		return errors.New("choose an interval from 1 to 1440 minutes")
	}
	decisions, err := a.changeTemporary(change)
	if err == nil && a.observe != nil {
		for _, decision := range decisions {
			a.observe(decision)
		}
	}
	return err
}

func (a *Authorizer) changeTemporary(change ui.DecisionChange) ([]Decision, error) {
	s := a.decisions
	s.mu.Lock()
	defer s.mu.Unlock()
	s.prune()
	for key, item := range s.items {
		if item.id != change.ID {
			continue
		}
		record := Decision{KeyFingerprint: key.key, HostFingerprint: key.server, User: key.user, Source: "management"}
		record.Process, record.ProcessPID, record.ProcessVersion = item.anchorName(), item.anchor.PID, item.anchor.Version
		switch change.Action {
		case "revoke":
			delete(s.items, key)
			record.Outcome = "revoked"
			return []Decision{record}, nil
		case "revoke-process":
			// The window names one row; the agent works out which other rows
			// were granted to the same running program. A row with no anchor
			// has no siblings, so this falls back to revoking just that row.
			if item.anchor.PID == 0 {
				delete(s.items, key)
				record.Outcome = "revoked"
				return []Decision{record}, nil
			}
			return s.revokeProcess(item.anchor), nil
		}
		scope := ui.GrantCustom
		if change.EndOfDay {
			scope = ui.GrantDay
		}
		if !item.allowed {
			scope = ui.DenyCustom
			if change.EndOfDay {
				scope = ui.DenyDay
			}
		}
		until, err := decisionExpiry(s.now(), ui.Confirmation{Allowed: item.allowed, Scope: scope, DurationMinutes: change.Minutes})
		if err != nil {
			return nil, err
		}
		item.expires = until
		s.items[key] = item
		record.Outcome = "updated"
		record.Scope = string(scope)
		record.ExpiresAt = &until
		return []Decision{record}, nil
	}
	return nil, errors.New("this decision has expired or was already revoked")
}

// revokeProcess drops every decision held by one process, identified by PID and
// PID version together so that a reused number cannot take a decision with it.
func (s *decisionStore) revokeProcess(anchor proc.Link) []Decision {
	var records []Decision
	for key, item := range s.items {
		if item.anchor.PID == 0 || !item.anchor.Same(anchor) {
			continue
		}
		delete(s.items, key)
		records = append(records, Decision{
			KeyFingerprint: key.key, HostFingerprint: key.server, User: key.user,
			Source: "management", Outcome: "revoked",
			Process: item.anchorName(), ProcessPID: item.anchor.PID, ProcessVersion: item.anchor.Version,
		})
	}
	sort.Slice(records, func(i, j int) bool {
		if records[i].KeyFingerprint == records[j].KeyFingerprint {
			return records[i].HostFingerprint < records[j].HostFingerprint
		}
		return records[i].KeyFingerprint < records[j].KeyFingerprint
	})
	return records
}
