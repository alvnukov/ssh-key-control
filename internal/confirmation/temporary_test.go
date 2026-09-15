package confirmation_test

import (
	"context"
	"github.com/alvnukov/ssh-key-control/internal/confirmation"
	"github.com/alvnukov/ssh-key-control/internal/ui"
	"sync"
	"testing"
	"time"
)

func TestTemporaryDecisionManagement(t *testing.T) {
	for _, allowed := range []bool{false, true} {
		t.Run(map[bool]string{false: "denial", true: "approval"}[allowed], func(t *testing.T) {
			now := time.Date(2026, 9, 13, 19, 0, 0, 0, time.FixedZone("local", 10800))
			scope := ui.Deny15Minutes
			if allowed {
				scope = ui.Grant15Minutes
			}
			d := &scopedDialogs{dialogs: dialogs{allowed: allowed}, scope: scope}
			var events []confirmation.Decision
			a := confirmation.NewWithObserver(d, func() time.Time { return now }, func(e confirmation.Decision) { events = append(events, e) })
			target := &confirmation.Destination{Host: "router", HostKey: "SHA256:server", User: "alice"}
			who := caller(session(firstTestPID, firstTestPID+1))
			authorize := func(key string) {
				t.Helper()
				got, err := a.Authorize(context.Background(), key, "", target, who)
				if err != nil || got != allowed {
					t.Fatalf("authorize=%v,%v", got, err)
				}
			}
			authorize("SHA256:key")
			authorize("SHA256:other-key")
			entries := a.TemporaryDecisions()
			if len(entries) != 2 {
				t.Fatalf("entries=%+v", entries)
			}
			var entry ui.TemporaryDecision
			for _, v := range entries {
				if v.KeyFingerprint == "SHA256:key" {
					entry = v
				}
			}
			if entry.ID == "" || entry.Allowed != allowed || entry.HostFingerprint != target.HostKey || entry.User != "alice" || entry.Host != "router" {
				t.Fatalf("wrong identity: %+v", entry)
			}
			if err := a.ChangeTemporaryDecision(ui.DecisionChange{Action: "update", ID: entry.ID, Minutes: 5}); err != nil {
				t.Fatal(err)
			}
			for _, v := range a.TemporaryDecisions() {
				if v.ID == entry.ID {
					if v.Allowed != entry.Allowed || v.KeyFingerprint != entry.KeyFingerprint || v.HostFingerprint != entry.HostFingerprint || v.User != entry.User {
						t.Fatal("update changed authority")
					}
					expiry, err := time.Parse(time.RFC3339, v.ExpiresAt)
					if err != nil || !expiry.Equal(now.Add(5*time.Minute)) {
						t.Fatalf("wrong expiry: %+v", v)
					}
				}
			}
			authorize("SHA256:key")
			if d.calls != 2 {
				t.Fatal("edited decision stopped being cached")
			}
			if err := a.ChangeTemporaryDecision(ui.DecisionChange{Action: "revoke", ID: entry.ID}); err != nil {
				t.Fatal(err)
			}
			if len(a.TemporaryDecisions()) != 1 {
				t.Fatal("revoked wrong entries")
			}
			authorize("SHA256:other-key")
			if d.calls != 2 {
				t.Fatal("revocation affected unrelated key")
			}
			authorize("SHA256:key")
			if d.calls != 3 {
				t.Fatal("revoked decision did not ask again")
			}
			if err := a.ChangeTemporaryDecision(ui.DecisionChange{Action: "update", ID: entry.ID, Minutes: 15}); err == nil {
				t.Fatal("stale ID resurrected decision")
			}
			var updated, revoked bool
			for _, e := range events {
				if e.Source == "management" {
					updated = updated || e.Outcome == "updated"
					revoked = revoked || e.Outcome == "revoked"
					if e.KeyFingerprint != "SHA256:key" || e.HostFingerprint != target.HostKey || e.User != "alice" {
						t.Fatal("wrong audit identity")
					}
				}
			}
			if !updated || !revoked {
				t.Fatal("missing management audit")
			}
		})
	}
}

func TestTemporaryDecisionExpiryAndInvalidEdits(t *testing.T) {
	now := time.Date(2026, 9, 13, 23, 50, 0, 0, time.FixedZone("local", 10800))
	d := &scopedDialogs{dialogs: dialogs{allowed: true}, scope: ui.Grant15Minutes}
	a := confirmation.New(d, func() time.Time { return now })
	if _, err := a.Authorize(context.Background(), "key", "", &confirmation.Destination{User: "u", HostKey: "host"}, nil); err != nil {
		t.Fatal(err)
	}
	entry := a.TemporaryDecisions()[0]
	for _, change := range []ui.DecisionChange{
		{Action: "update", ID: entry.ID}, {Action: "update", ID: entry.ID, Minutes: -1},
		{Action: "update", ID: entry.ID, Minutes: 1441}, {Action: "update", ID: entry.ID, Minutes: 5, EndOfDay: true},
		{Action: "revoke", ID: entry.ID, Minutes: 1}, {Action: "grant", ID: entry.ID, Minutes: 5},
		{Action: "update", ID: "unknown", Minutes: 5},
	} {
		if err := a.ChangeTemporaryDecision(change); err == nil {
			t.Fatalf("accepted %+v", change)
		}
		if got := a.TemporaryDecisions(); len(got) != 1 || got[0] != entry {
			t.Fatal("invalid edit mutated store")
		}
	}
	if err := a.ChangeTemporaryDecision(ui.DecisionChange{Action: "update", ID: entry.ID, EndOfDay: true}); err != nil {
		t.Fatal(err)
	}
	expiry, _ := time.Parse(time.RFC3339, a.TemporaryDecisions()[0].ExpiresAt)
	if !expiry.Equal(time.Date(2026, 9, 14, 0, 0, 0, 0, now.Location())) {
		t.Fatal("end-of-day used wrong timezone")
	}
	now = expiry
	if len(a.TemporaryDecisions()) != 0 {
		t.Fatal("expired decision still visible")
	}
	if err := a.ChangeTemporaryDecision(ui.DecisionChange{Action: "update", ID: entry.ID, Minutes: 5}); err == nil {
		t.Fatal("expired decision resurrected")
	}
}

type managementBlockingDialogs struct {
	dialogs
	entered chan struct{}
	release chan struct{}
}

func (d *managementBlockingDialogs) ConfirmScoped(_ context.Context, r ui.ConfirmRequest) (ui.Confirmation, error) {
	if r.Destination == "u @ blocked" {
		close(d.entered)
		<-d.release
	}
	return ui.Confirmation{Allowed: true, Scope: ui.Grant15Minutes}, nil
}
func TestTemporaryManagementWhileConfirmationOpen(t *testing.T) {
	d := &managementBlockingDialogs{entered: make(chan struct{}), release: make(chan struct{})}
	a := confirmation.New(d, nil)
	if _, err := a.Authorize(context.Background(), "key", "", &confirmation.Destination{Host: "first", User: "u", HostKey: "host"}, nil); err != nil {
		t.Fatal(err)
	}
	entry := a.TemporaryDecisions()[0]
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, _ = a.Authorize(context.Background(), "other", "", &confirmation.Destination{Host: "blocked", User: "u", HostKey: "other-host"}, nil)
	}()
	<-d.entered
	defer func() { close(d.release); wg.Wait() }()
	done := make(chan error, 1)
	go func() {
		_ = a.TemporaryDecisions()
		done <- a.ChangeTemporaryDecision(ui.DecisionChange{Action: "revoke", ID: entry.ID})
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("management blocked on unrelated confirmation")
	}
}
