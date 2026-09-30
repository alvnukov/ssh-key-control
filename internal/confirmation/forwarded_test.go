package confirmation_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/alvnukov/ssh-key-control/internal/confirmation"
	"github.com/alvnukov/ssh-key-control/internal/ui"
)

type forwardedDialogs struct {
	dialogs
	requests []ui.ConfirmRequest
	answer   ui.Confirmation
	after    func()
}

func (d *forwardedDialogs) ConfirmScoped(_ context.Context, req ui.ConfirmRequest) (ui.Confirmation, error) {
	d.requests = append(d.requests, req)
	if d.after != nil {
		d.after()
	}
	return d.answer, d.err
}

func forwardedDestination() *confirmation.Destination {
	return &confirmation.Destination{Host: "terminal", User: "alice", HostKey: "SHA256:terminal"}
}

func TestForwardedApprovalsBypassDirectLeasesAndNeverCreateThem(t *testing.T) {
	for _, anchored := range []bool{false, true} {
		t.Run(map[bool]string{false: "broad", true: "anchored"}[anchored], func(t *testing.T) {
			d := &forwardedDialogs{answer: ui.Confirmation{Allowed: true, Scope: ui.Grant5Minutes}}
			var events []confirmation.Decision
			a := confirmation.NewWithObserver(d, time.Now, func(event confirmation.Decision) { events = append(events, event) })
			var who confirmation.Caller
			if anchored {
				who = caller(session(firstTestPID, firstTestPID+1))
			}
			for range 2 {
				if ok, err := a.Authorize(context.Background(), "SHA256:key", "key", forwardedDestination(), who); err != nil || !ok {
					t.Fatalf("direct approval: %v %v", ok, err)
				}
			}
			if len(d.requests) != 1 {
				t.Fatal("direct lease regression")
			}
			d.answer = ui.Confirmation{Allowed: false, Scope: ui.GrantOnce}
			for range 2 {
				if ok, err := a.AuthorizeForwarded(context.Background(), "SHA256:key", "key", forwardedDestination(), []string{"SHA256:jump"}); err != nil || ok {
					t.Fatalf("direct grant reused by forwarded request: %v %v", ok, err)
				}
			}
			if len(d.requests) != 3 {
				t.Fatal("forwarded request did not prompt each time")
			}
			for _, req := range d.requests[1:] {
				if !req.OnceOnly || req.Destination != "alice @ terminal" || len(req.Chain) != 0 || req.Boundary != 0 || !strings.Contains(req.Message, "SHA256:jump") || !strings.Contains(req.Message, "remote process is not attested") || strings.Contains(req.Message, "not verified") {
					t.Fatalf("misleading forwarded UI: %+v", req)
				}
			}
			if len(a.TemporaryDecisions()) != 1 {
				t.Fatal("forwarded denial changed direct lease")
			}
			for _, event := range events[len(events)-2:] {
				if event.Source != "prompt" || event.Scope != "once" || event.HostFingerprint != "SHA256:terminal" || event.User != "alice" || event.ProcessPID != 0 {
					t.Fatalf("wrong forwarded history: %+v", event)
				}
			}
			d.answer = ui.Confirmation{Allowed: true, Scope: ui.GrantOnce}
			b := confirmation.New(d, time.Now)
			for range 2 {
				if ok, err := b.AuthorizeForwarded(context.Background(), "SHA256:key", "key", forwardedDestination(), []string{"SHA256:jump"}); err != nil || !ok {
					t.Fatalf("forwarded approval: %v %v", ok, err)
				}
			}
			if len(b.TemporaryDecisions()) != 0 {
				t.Fatal("forwarded approval created a lease")
			}
			before := len(d.requests)
			if ok, err := b.Authorize(context.Background(), "SHA256:key", "key", forwardedDestination(), nil); err != nil || !ok {
				t.Fatalf("direct approval: %v %v", ok, err)
			}
			if len(d.requests) != before+1 {
				t.Fatal("direct request inherited forwarded approval")
			}
		})
	}
}

func TestForwardedRequiresStrictOneShotAnswer(t *testing.T) {
	for _, answer := range []ui.Confirmation{
		{Allowed: true, Scope: ui.Grant5Minutes},
		{Allowed: false, Scope: ui.Deny5Minutes},
		{Allowed: true, Scope: ui.GrantOnce, DurationMinutes: 1},
		{Allowed: true, Scope: ui.GrantOnce, Boundary: 1},
		{Allowed: true},
	} {
		d := &forwardedDialogs{answer: answer}
		a := confirmation.New(d, time.Now)
		if ok, err := a.AuthorizeForwarded(context.Background(), "key", "", forwardedDestination(), []string{"jump"}); err == nil || ok {
			t.Fatalf("invalid one-shot answer accepted: %+v", answer)
		}
		if len(a.TemporaryDecisions()) != 0 {
			t.Fatal("invalid forwarded answer created a lease")
		}
	}
}

func TestCancelledForwardedApprovalCannotAuthorize(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d := &forwardedDialogs{answer: ui.Confirmation{Allowed: true, Scope: ui.GrantOnce}, after: cancel}
	a := confirmation.New(d, time.Now)
	if ok, err := a.AuthorizeForwarded(ctx, "key", "", forwardedDestination(), []string{"jump"}); err != context.Canceled || ok {
		t.Fatalf("late approval: %v %v", ok, err)
	}
	if len(a.TemporaryDecisions()) != 0 {
		t.Fatal("late forwarded answer created a lease")
	}
}

func TestForwardedApprovalCannotReuseOrReplaceDirectDenial(t *testing.T) {
	d := &forwardedDialogs{answer: ui.Confirmation{Allowed: false, Scope: ui.Deny5Minutes}}
	a := confirmation.New(d, time.Now)
	who := caller(session(firstTestPID, firstTestPID+1))
	if ok, err := a.Authorize(context.Background(), "key", "", forwardedDestination(), who); err != nil || ok {
		t.Fatalf("direct denial: %v %v", ok, err)
	}
	d.answer = ui.Confirmation{Allowed: true, Scope: ui.GrantOnce}
	if ok, err := a.AuthorizeForwarded(context.Background(), "key", "", forwardedDestination(), []string{"jump"}); err != nil || !ok {
		t.Fatalf("direct denial reused for forwarded request: %v %v", ok, err)
	}
	if ok, err := a.Authorize(context.Background(), "key", "", forwardedDestination(), who); err != nil || ok {
		t.Fatalf("forwarded approval changed direct denial: %v %v", ok, err)
	}
	if len(d.requests) != 2 || len(a.TemporaryDecisions()) != 1 {
		t.Fatal("forwarded approval changed direct decision storage")
	}
}
