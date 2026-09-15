package helper

import (
	"context"
	"testing"

	"github.com/alvnukov/ssh-key-control/internal/ui"
)

// asking is a confirmation for a caller three processes deep, with the middle
// one proposed as the link a decision would attach to.
func asking(title string, scope string) ui.ConfirmRequest {
	return ui.ConfirmRequest{
		Title:       title,
		Message:     scope,
		Destination: "alice@production",
		Chain: []ui.ProcessLink{
			{Name: "ssh", PID: 101},
			{Name: "zsh", PID: 102},
			{Name: "Terminal", PID: 103, Team: "APPLE", Verified: true},
		},
		Boundary: 1,
	}
}

func TestTheChainAndTheProposedBoundaryReachTheHelper(t *testing.T) {
	c := start(t)
	answer, err := c.ConfirmScoped(context.Background(), asking("boundary echo", "15m"))
	if err != nil {
		t.Fatalf("ConfirmScoped: %v", err)
	}
	if !answer.Allowed || answer.Scope != ui.Grant15Minutes || answer.Boundary != 1 {
		t.Fatalf("answer = %+v, want the proposed boundary accepted unchanged", answer)
	}
}

func TestTheUserMayMoveTheBoundaryUpTheChain(t *testing.T) {
	c := start(t)
	answer, err := c.ConfirmScoped(context.Background(), asking("boundary widen", "15m"))
	if err != nil {
		t.Fatalf("ConfirmScoped: %v", err)
	}
	if answer.Boundary != 2 {
		t.Fatalf("boundary = %d, want 2: the user chose the ancestor above", answer.Boundary)
	}
}

func TestABoundaryTheHelperShouldNotHaveSentIsRefused(t *testing.T) {
	for _, tc := range []struct {
		name string
		req  ui.ConfirmRequest
	}{
		{"below the proposed link", asking("boundary below", "15m")},
		{"past the end of the chain", asking("boundary offchain", "15m")},
		{"past the end of the chain on a refusal", asking("boundary denied offchain", "deny5m")},
		{"when no boundary was offered", func() ui.ConfirmRequest {
			req := asking("boundary unasked", "15m")
			req.Boundary = 0
			return req
		}()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := start(t)
			answer, err := c.ConfirmScoped(context.Background(), tc.req)
			if err == nil || answer.Allowed || answer.Boundary != 0 {
				t.Fatalf("answer = %+v, %v; want a closed failure", answer, err)
			}
		})
	}
}

// A refusal is drawn at a program exactly as an approval is, so the helper is
// allowed to say where the user left the line on the way out.
func TestARefusalNamesTheProgramItWasDrawnAt(t *testing.T) {
	for _, tc := range []struct {
		name  string
		title string
		scope ui.GrantScope
		want  int
	}{
		{"at the link that was proposed", "boundary denied", ui.Deny5Minutes, 1},
		{"at the ancestor the user moved it up to", "boundary denied widen", ui.Deny15Minutes, 2},
		{"for as long as that program runs", "boundary denied", ui.DenyProcess, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := start(t)
			answer, err := c.ConfirmScoped(context.Background(), asking(tc.title, string(tc.scope)))
			if err != nil {
				t.Fatalf("ConfirmScoped: %v", err)
			}
			if answer.Allowed || answer.Scope != tc.scope || answer.Boundary != tc.want {
				t.Fatalf("answer = %+v, want %s refused at link %d", answer, tc.scope, tc.want)
			}
		})
	}
}

func TestADecisionLastingAsLongAsAProcessNeedsOneNamed(t *testing.T) {
	// Neither answer may be measured against a program when the dialog had
	// none to offer: "while it runs" needs an it.
	for _, scope := range []ui.GrantScope{ui.GrantProcess, ui.DenyProcess} {
		t.Run(string(scope), func(t *testing.T) {
			c := start(t)
			// These titles answer with the scope they are handed and send no
			// boundary of their own, so the missing one is what is tested.
			title := "forced scope"
			if scope.IsDenyDuration() {
				title = "deny me"
			}
			req := asking(title, string(scope))
			req.Boundary = 0
			answer, err := c.ConfirmScoped(context.Background(), req)
			if err == nil || answer.Allowed {
				t.Fatalf("answer = %+v, %v; want a closed failure", answer, err)
			}
		})
	}
}

func TestLegacyConfirmShowsTheChainWithoutOfferingABoundary(t *testing.T) {
	c := start(t)
	// The fake helper refuses outright if it is offered a boundary here.
	allowed, err := c.Confirm(context.Background(), asking("legacy", ""))
	if err != nil || !allowed {
		t.Fatalf("Confirm = %v, %v", allowed, err)
	}
}
