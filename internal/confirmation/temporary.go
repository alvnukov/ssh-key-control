package confirmation

import (
	"crypto/rand"
	"errors"
	"sort"
	"sync"
	"time"

	"github.com/alvnukov/ssh-key-control/internal/ui"
)

type temporaryDecision struct {
	id, host string
	allowed  bool
	expires  time.Time
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

func (s *decisionStore) remember(key grantKey, host string, choice ui.Confirmation) (time.Time, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.items, key)
	until, err := decisionExpiry(s.now(), choice)
	if err != nil {
		return time.Time{}, err
	}
	if !until.IsZero() {
		s.items[key] = temporaryDecision{rand.Text(), clean(host), choice.Allowed, until}
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
		items = append(items, ui.TemporaryDecision{
			ID: item.id, KeyFingerprint: key.key, HostFingerprint: key.server,
			Host: item.host, User: key.user, Allowed: item.allowed,
			ExpiresAt: item.expires.UTC().Format(time.RFC3339),
		})
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
	if change.Action != "revoke" && change.Action != "update" {
		return errors.New("unknown temporary decision action")
	}
	if change.Action == "revoke" && (change.Minutes != 0 || change.EndOfDay) {
		return errors.New("revoking a decision cannot specify a duration")
	}
	if change.Action == "update" && ((change.EndOfDay && change.Minutes != 0) ||
		(!change.EndOfDay && (change.Minutes < 1 || change.Minutes > 1440))) {
		return errors.New("choose an interval from 1 to 1440 minutes")
	}
	decision, err := a.changeTemporary(change)
	if err == nil && a.observe != nil {
		a.observe(decision)
	}
	return err
}

func (a *Authorizer) changeTemporary(change ui.DecisionChange) (Decision, error) {
	s := a.decisions
	s.mu.Lock()
	defer s.mu.Unlock()
	s.prune()
	for key, item := range s.items {
		if item.id != change.ID {
			continue
		}
		record := Decision{KeyFingerprint: key.key, HostFingerprint: key.server, User: key.user, Source: "management"}
		if change.Action == "revoke" {
			delete(s.items, key)
			record.Outcome = "revoked"
			return record, nil
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
			return Decision{}, err
		}
		item.expires = until
		s.items[key] = item
		record.Outcome = "updated"
		record.Scope = string(scope)
		record.ExpiresAt = &until
		return record, nil
	}
	return Decision{}, errors.New("this decision has expired or was already revoked")
}
