package confirmation_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/alvnukov/ssh-key-control/internal/confirmation"
	"github.com/alvnukov/ssh-key-control/internal/proc"
	"github.com/alvnukov/ssh-key-control/internal/ui"
)

// PIDs here are far above anything macOS will hand out, so a chain invented by
// a test can never be confused with a process on the machine running it.
const firstTestPID = 900001

var testNow = time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)

// link describes one process as the kernel would: a PID and PID version that
// name it, a controlling terminal, and how long it has been running.
func link(pid int32, name string, tty uint32, age time.Duration) proc.Link {
	return proc.Link{PID: pid, Version: uint32(pid), Name: name, TTY: tty, TTYKnown: true, Start: testNow.Add(-age)}
}

func chainOf(links ...proc.Link) proc.Chain {
	return proc.Chain{Links: links, Complete: true}
}

// session is one ssh a moment old under a shell that has been up for an hour,
// both on the same terminal: the ordinary case, anchored on the shell.
func session(sshPID, shellPID int32) proc.Chain {
	return chainOf(link(sshPID, "ssh", 17, time.Second), link(shellPID, "zsh", 17, time.Hour))
}

func caller(chains ...proc.Chain) confirmation.Caller {
	i := 0
	return func() proc.Chain {
		c := chains[min(i, len(chains)-1)]
		i++
		return c
	}
}

// chainDialogs answers confirmations and keeps what it was shown, so a test can
// assert on the chain the user would have seen as well as on the decision.
type chainDialogs struct {
	ui.Dialogs
	requests []ui.ConfirmRequest
	allowed  bool
	scope    ui.GrantScope
	boundary int
	err      error
}

func (d *chainDialogs) Confirm(_ context.Context, req ui.ConfirmRequest) (bool, error) {
	d.requests = append(d.requests, req)
	return d.allowed, d.err
}

func (d *chainDialogs) ConfirmScoped(_ context.Context, req ui.ConfirmRequest) (ui.Confirmation, error) {
	d.requests = append(d.requests, req)
	return ui.Confirmation{Allowed: d.allowed, Scope: d.scope, Boundary: d.boundary}, d.err
}

func (d *chainDialogs) prompts() int { return len(d.requests) }

func server() *confirmation.Destination {
	return &confirmation.Destination{Host: "host", User: "alice", HostKey: "SHA256:server"}
}

func allow(t *testing.T, a *confirmation.Authorizer, c confirmation.Caller) {
	t.Helper()
	ok, err := a.Authorize(context.Background(), "SHA256:key", "", server(), c)
	if err != nil || !ok {
		t.Fatalf("Authorize = %t, %v; want an approval", ok, err)
	}
}

func TestAnApprovalBelongsToTheProcessThatAskedForIt(t *testing.T) {
	d := &chainDialogs{allowed: true, scope: ui.Grant15Minutes}
	a := confirmation.New(d, func() time.Time { return testNow })
	shell, other := int32(firstTestPID+1), int32(firstTestPID+2)

	allow(t, a, caller(session(firstTestPID, shell)))
	if d.prompts() != 1 {
		t.Fatalf("got %d prompts for the first request, want 1", d.prompts())
	}
	// A second ssh started by the same shell is covered by the same decision.
	allow(t, a, caller(session(firstTestPID+10, shell)))
	if d.prompts() != 1 {
		t.Fatal("the shell that was approved was asked again")
	}
	// A different shell was never approved, whatever it wants to sign.
	allow(t, a, caller(session(firstTestPID+20, other)))
	if d.prompts() != 2 {
		t.Fatalf("got %d prompts, want 2: an approval reached a shell that never asked", d.prompts())
	}
}

func deny(t *testing.T, a *confirmation.Authorizer, c confirmation.Caller) {
	t.Helper()
	ok, err := a.Authorize(context.Background(), "SHA256:key", "", server(), c)
	if err != nil || ok {
		t.Fatalf("Authorize = %t, %v; want a refusal", ok, err)
	}
}

func TestARefusalSilencesTheProgramItWasDrawnAtAndNobodyElse(t *testing.T) {
	d := &chainDialogs{allowed: false, scope: ui.Deny5Minutes}
	a := confirmation.New(d, func() time.Time { return testNow })
	shell, other := int32(firstTestPID+1), int32(firstTestPID+2)

	deny(t, a, caller(session(firstTestPID, shell)))
	// The program that was turned away stops asking, however often it tries.
	deny(t, a, caller(session(firstTestPID+10, shell)))
	if d.prompts() != 1 {
		t.Fatalf("got %d prompts, want 1: the refused program asked again", d.prompts())
	}
	// Another shell was never refused. Silencing it would refuse the user's
	// own next connection for something they never saw.
	deny(t, a, caller(session(firstTestPID+20, other)))
	if d.prompts() != 2 {
		t.Fatalf("got %d prompts, want 2: a refusal reached a program that never asked", d.prompts())
	}
}

func TestARefusalWithNoAncestryAnswersOnceAndIsGone(t *testing.T) {
	d := &chainDialogs{allowed: false, scope: ui.Deny5Minutes}
	a := confirmation.New(d, func() time.Time { return testNow })

	deny(t, a, nil)
	deny(t, a, nil)
	if d.prompts() != 2 {
		t.Fatal("a refusal that could name nobody was kept against everybody")
	}
	if len(a.TemporaryDecisions()) != 0 {
		t.Fatal("a refusal nobody could see was left standing in the window")
	}
	// Least of all does it reach a program that does have a name.
	deny(t, a, caller(session(firstTestPID, firstTestPID+1)))
	if d.prompts() != 3 {
		t.Fatalf("got %d prompts, want 3: an unanchored refusal silenced a named program", d.prompts())
	}
}

func TestARefusalAtAnAncestorOutranksAnApprovalBelowIt(t *testing.T) {
	d := &chainDialogs{allowed: true, scope: ui.Grant15Minutes, boundary: 1}
	a := confirmation.New(d, func() time.Time { return testNow })
	shell, term := int32(firstTestPID+1), int32(firstTestPID+3)

	// The shell inside the terminal is approved for fifteen minutes.
	allow(t, a, caller(settled(firstTestPID, shell, term)))
	// The terminal is then refused, which is what "stop asking me from this
	// window" has to mean: everything that window starts is refused with it.
	d.allowed, d.scope, d.boundary = false, ui.Deny5Minutes, 2
	deny(t, a, caller(pane(firstTestPID+10, firstTestPID+11, term)))
	deny(t, a, caller(settled(firstTestPID+20, shell, term)))
	if d.prompts() != 2 {
		t.Fatalf("got %d prompts, want 2: an approval survived a refusal drawn above it", d.prompts())
	}
}

func TestARefusalMeasuredAgainstAProgramLastsWhileItRuns(t *testing.T) {
	d := &chainDialogs{allowed: false, scope: ui.DenyProcess}
	now := testNow
	a := confirmation.New(d, func() time.Time { return now })
	shell := int32(firstTestPID + 1)

	deny(t, a, caller(session(firstTestPID, shell)))
	now = now.Add(23 * time.Hour)
	// Whatever asks in a loop keeps being refused for as long as it runs,
	// without a dialog and without touching anything else.
	deny(t, a, caller(session(firstTestPID+10, shell)))
	if d.prompts() != 1 {
		t.Fatal("a refusal made for a running program did not last while it ran")
	}
	row := a.TemporaryDecisions()
	if len(row) != 1 || row[0].Allowed || row[0].ProcessPID != shell {
		t.Fatalf("decisions = %+v, want one refusal held by the program it names", row)
	}
	// Its replacement is a different process and is asked afresh.
	deny(t, a, caller(session(firstTestPID+20, firstTestPID+2)))
	if d.prompts() != 2 {
		t.Fatalf("got %d prompts, want 2: a dead program kept refusing on behalf of its successor", d.prompts())
	}
}

func TestARefusalCannotLastAsLongAsAProcessNobodyNamed(t *testing.T) {
	d := &chainDialogs{allowed: false, scope: ui.DenyProcess}
	a := confirmation.New(d, func() time.Time { return testNow })
	deny(t, a, nil)
	deny(t, a, nil)
	if d.prompts() != 2 {
		t.Fatal("a refusal measured against a program was stored without one")
	}
	if len(a.TemporaryDecisions()) != 0 {
		t.Fatal("a refusal with no anchor was listed as lasting while its program runs")
	}
}

func TestAnApprovalWithNoAncestryIsNotLentToProgramsThatHaveOne(t *testing.T) {
	d := &chainDialogs{allowed: true, scope: ui.Grant15Minutes}
	a := confirmation.New(d, func() time.Time { return testNow })

	allow(t, a, nil)
	allow(t, a, nil)
	if d.prompts() != 1 {
		t.Fatal("an approval made without any ancestry was not reused for the same")
	}
	allow(t, a, caller(session(firstTestPID, firstTestPID+1)))
	if d.prompts() != 2 {
		t.Fatal("an approval that named no program was handed to one that has a name")
	}
}

func TestTheDialogShowsWhoIsAskingAndWhereADecisionWouldAttach(t *testing.T) {
	d := &chainDialogs{allowed: true, scope: ui.GrantOnce}
	a := confirmation.New(d, func() time.Time { return testNow })
	allow(t, a, caller(session(firstTestPID, firstTestPID+1)))

	req := d.requests[0]
	if len(req.Chain) != 2 || req.Chain[0].Name != "ssh" || req.Chain[1].Name != "zsh" {
		t.Fatalf("chain = %+v, want the caller and its shell, nearest first", req.Chain)
	}
	if req.Chain[0].PID != firstTestPID || req.Chain[1].PID != firstTestPID+1 {
		t.Fatalf("chain = %+v, want each process named with its own PID", req.Chain)
	}
	if req.Boundary != 1 {
		t.Fatalf("boundary = %d, want 1: the shell is what outlives this request", req.Boundary)
	}
}

func TestAnUnverifiedDestinationShowsTheChainWithoutOfferingABoundary(t *testing.T) {
	d := &chainDialogs{allowed: true}
	a := confirmation.New(d, func() time.Time { return testNow })
	if ok, err := a.Authorize(context.Background(), "SHA256:key", "", nil, caller(session(firstTestPID, firstTestPID+1))); err != nil || !ok {
		t.Fatalf("Authorize = %t, %v", ok, err)
	}
	req := d.requests[0]
	if len(req.Chain) != 2 {
		t.Fatalf("chain = %+v, want the caller shown even for a single signature", req.Chain)
	}
	if req.Boundary != 0 {
		t.Fatalf("boundary = %d, want none: nothing durable is on offer here", req.Boundary)
	}
}

// pane is a shell in a fresh terminal pane: the shell is as young as the ssh it
// started, so only the terminal itself is old enough to hold a decision.
func pane(sshPID, shellPID, termPID int32) proc.Chain {
	return chainOf(
		link(sshPID, "ssh", 17, time.Second),
		link(shellPID, "zsh", 17, 2*time.Second),
		link(termPID, "tmux", proc.NoTTY, 3*time.Hour),
	)
}

func TestTheUserMayWidenADecisionUpTheChainButNeverDownIt(t *testing.T) {
	term := int32(firstTestPID + 3)
	t.Run("widened to the terminal", func(t *testing.T) {
		d := &chainDialogs{allowed: true, scope: ui.Grant15Minutes, boundary: 2}
		a := confirmation.New(d, func() time.Time { return testNow })
		allow(t, a, caller(pane(firstTestPID, firstTestPID+1, term)))
		// A different shell, in a different pane of the same terminal.
		allow(t, a, caller(pane(firstTestPID+10, firstTestPID+11, term)))
		if d.prompts() != 1 {
			t.Fatalf("got %d prompts, want 1: the terminal was approved, not one pane", d.prompts())
		}
	})
	t.Run("narrowed below the proposed link", func(t *testing.T) {
		d := &chainDialogs{allowed: true, scope: ui.Grant15Minutes, boundary: 1}
		a := confirmation.New(d, func() time.Time { return testNow })
		allow(t, a, caller(pane(firstTestPID, firstTestPID+1, term)))
		allow(t, a, caller(pane(firstTestPID+10, firstTestPID+11, term)))
		if d.prompts() != 1 {
			t.Fatalf("got %d prompts, want 1: a decision was pinned to a shell that had already gone", d.prompts())
		}
	})
}

// settled is a shell that has been open for an hour inside the same terminal:
// old enough that a decision would attach to the shell rather than to tmux.
func settled(sshPID, shellPID, termPID int32) proc.Chain {
	return chainOf(
		link(sshPID, "ssh", 17, time.Second),
		link(shellPID, "zsh", 17, time.Hour),
		link(termPID, "tmux", proc.NoTTY, 3*time.Hour),
	)
}

func TestADecisionGivenToATerminalCoversTheShellsInsideIt(t *testing.T) {
	d := &chainDialogs{allowed: true, scope: ui.Grant15Minutes, boundary: 2}
	a := confirmation.New(d, func() time.Time { return testNow })
	term := int32(firstTestPID + 3)

	// Approved from a fresh pane, widened by the user to the terminal itself.
	allow(t, a, caller(pane(firstTestPID, firstTestPID+1, term)))
	if d.requests[0].Boundary != 2 {
		t.Fatalf("boundary = %d, want 2: nothing below the terminal is old enough", d.requests[0].Boundary)
	}
	// An established shell in the same terminal would be offered a decision of
	// its own, but the one the terminal already holds answers for it.
	allow(t, a, caller(settled(firstTestPID+10, firstTestPID+11, term)))
	if d.prompts() != 1 {
		t.Fatalf("got %d prompts, want 1: a decision made for the terminal did not reach a shell inside it", d.prompts())
	}
}

func TestNothingIsRememberedWhenTheAncestryChangesWhileTheDialogIsOpen(t *testing.T) {
	d := &chainDialogs{allowed: true, scope: ui.Grant15Minutes}
	a := confirmation.New(d, func() time.Time { return testNow })
	shown := session(firstTestPID, firstTestPID+1)
	// The second read is the one taken after the dialog closes.
	moved := caller(shown, session(firstTestPID, firstTestPID+2))

	allow(t, a, moved)
	allow(t, a, caller(shown))
	if d.prompts() != 2 {
		t.Fatalf("got %d prompts, want 2: a decision was stored for a chain nobody was shown", d.prompts())
	}
}

func TestADecisionMadeForARunningProgramEndsWithIt(t *testing.T) {
	d := &chainDialogs{allowed: true, scope: ui.GrantProcess}
	now := testNow
	a := confirmation.New(d, func() time.Time { return now })
	shell := int32(firstTestPID + 1)

	allow(t, a, caller(session(firstTestPID, shell)))
	now = now.Add(23 * time.Hour)
	allow(t, a, caller(session(firstTestPID+10, shell)))
	if d.prompts() != 1 {
		t.Fatal("a decision made for a running shell did not last while it ran")
	}
	// The shell is gone; its replacement has the same name and a new identity.
	allow(t, a, caller(session(firstTestPID+20, firstTestPID+2)))
	if d.prompts() != 2 {
		t.Fatalf("got %d prompts, want 2: a dead shell kept its decision", d.prompts())
	}
	// A day is the outer bound however long the program lives.
	now = testNow.Add(24*time.Hour + time.Second)
	allow(t, a, caller(session(firstTestPID+30, shell)))
	if d.prompts() != 3 {
		t.Fatal("a decision outlived the day it was capped at")
	}
}

func TestADecisionCannotLastAsLongAsAProcessNobodyNamed(t *testing.T) {
	d := &chainDialogs{allowed: true, scope: ui.GrantProcess}
	a := confirmation.New(d, func() time.Time { return testNow })
	allow(t, a, nil)
	allow(t, a, nil)
	if d.prompts() != 2 {
		t.Fatal("a process-long decision was stored without a process")
	}
	if len(a.TemporaryDecisions()) != 0 {
		t.Fatal("a decision with no anchor was listed as lasting while its program runs")
	}
}

func TestTheDecisionListNamesTheProgramEachDecisionWasGivenTo(t *testing.T) {
	d := &chainDialogs{allowed: true, scope: ui.Grant15Minutes}
	a := confirmation.New(d, func() time.Time { return testNow })
	shell := int32(firstTestPID + 1)
	allow(t, a, caller(session(firstTestPID, shell)))

	rows := a.TemporaryDecisions()
	if len(rows) != 1 {
		t.Fatalf("got %d decisions, want 1", len(rows))
	}
	if rows[0].Process != "zsh" || rows[0].ProcessPID != shell {
		t.Fatalf("decision = %+v, want it named after the shell that was approved", rows[0])
	}
	if rows[0].ProcessLive {
		t.Fatal("a process that cannot exist was reported as running")
	}
}

func TestRevokingAProgramTakesEveryDecisionItHeld(t *testing.T) {
	d := &chainDialogs{allowed: true, scope: ui.Grant15Minutes}
	a := confirmation.New(d, func() time.Time { return testNow })
	shell, other := int32(firstTestPID+1), int32(firstTestPID+2)
	mine := func(key string, c confirmation.Caller) {
		t.Helper()
		if ok, err := a.Authorize(context.Background(), key, "", server(), c); err != nil || !ok {
			t.Fatalf("Authorize = %t, %v", ok, err)
		}
	}
	mine("SHA256:key", caller(session(firstTestPID, shell)))
	mine("SHA256:other-key", caller(session(firstTestPID, shell)))
	mine("SHA256:key", caller(session(firstTestPID+10, other)))

	rows := a.TemporaryDecisions()
	if len(rows) != 3 {
		t.Fatalf("got %d decisions, want 3", len(rows))
	}
	var pick string
	for _, row := range rows {
		if row.ProcessPID == shell {
			pick = row.ID
		}
	}
	if err := a.ChangeTemporaryDecision(ui.DecisionChange{Action: "revoke-process", ID: pick}); err != nil {
		t.Fatalf("revoke-process: %v", err)
	}
	left := a.TemporaryDecisions()
	if len(left) != 1 || left[0].ProcessPID != other {
		t.Fatalf("left = %+v, want only the decision another program held", left)
	}
}

func TestRevokingAProgramCannotCarryADuration(t *testing.T) {
	d := &chainDialogs{allowed: true, scope: ui.Grant15Minutes}
	a := confirmation.New(d, func() time.Time { return testNow })
	allow(t, a, caller(session(firstTestPID, firstTestPID+1)))
	id := a.TemporaryDecisions()[0].ID
	if err := a.ChangeTemporaryDecision(ui.DecisionChange{Action: "revoke-process", ID: id, Minutes: 30}); err == nil {
		t.Fatal("a revocation was accepted with a duration attached")
	}
	if len(a.TemporaryDecisions()) != 1 {
		t.Fatal("a rejected change still altered the decisions")
	}
}

func TestAFailedDialogLeavesNoDecisionBehind(t *testing.T) {
	d := &chainDialogs{allowed: true, scope: ui.Grant15Minutes, err: errors.New("helper is gone")}
	a := confirmation.New(d, func() time.Time { return testNow })
	if ok, err := a.Authorize(context.Background(), "SHA256:key", "", server(), caller(session(firstTestPID, firstTestPID+1))); ok || err == nil {
		t.Fatalf("Authorize = %t, %v; want the failure reported", ok, err)
	}
	if len(a.TemporaryDecisions()) != 0 {
		t.Fatal("a dialog that failed still left a decision")
	}
}
