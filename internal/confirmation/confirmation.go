// Package confirmation owns explicit, in-memory approvals for agent signatures.
package confirmation

import (
	"context"
	"fmt"
	"strings"
	"time"
	"unicode"

	"github.com/alvnukov/ssh-key-control/internal/proc"
	"github.com/alvnukov/ssh-key-control/internal/ui"
)

// Destination comes only from a verified SSH session binding and the signed
// user-authentication payload. Host is a display label, not proof of identity.
// HostKey, not a caller-supplied hostname, identifies the server.
type Destination struct {
	Host, User, HostKey string
}

// grantKey is what a temporary decision is remembered against. An empty anchor
// means every program on this machine, which is where an approval goes when the
// caller's ancestry could not be read at all. A refusal never lands there: a
// refusal nobody could attach to a program would silence the user's own work
// with no window to say why, so an unanchored refusal answers once and is gone.
type grantKey struct{ key, server, user, anchor string }

// Caller reports the live process ancestry behind a request. Authorize asks
// twice, once before the dialog and once after it closes, so that a decision
// is never remembered for an ancestry the user was not shown.
type Caller func() proc.Chain

type Dialogs interface {
	Confirm(context.Context, ui.ConfirmRequest) (bool, error)
}

type Authorizer struct {
	observe   func(Decision)
	gate      chan struct{}
	dialogs   Dialogs
	now       func() time.Time
	decisions *decisionStore
}

func New(dialogs Dialogs, now func() time.Time) *Authorizer {
	return NewWithObserver(dialogs, now, nil)
}

// NewWithObserver records decisions after releasing the dialog queue.
func NewWithObserver(dialogs Dialogs, now func() time.Time, observe func(Decision)) *Authorizer {
	if now == nil {
		now = time.Now
	}
	return &Authorizer{observe: observe, gate: make(chan struct{}, 1), dialogs: dialogs, now: now, decisions: newDecisionStore(now)}
}

// Authorize serializes dialogs. An unknown destination always prompts, even if
// this key has a grant elsewhere. No approval is written to disk.
//
// Both answers are remembered against the caller's own ancestry, so a decision
// belongs to the shell or application that asked and not to every program
// running as this user. The dialog is what draws the line, and a refusal obeys
// the same line as an approval: refusing "everything" would punish the user's
// own next connection instead of whatever they just turned away, and do it
// silently, because a refusal already in hand shows no window.
func (a *Authorizer) Authorize(ctx context.Context, fingerprint, comment string, destination *Destination, caller Caller) (allowed bool, resultErr error) {
	decision := Decision{KeyFingerprint: fingerprint, Source: "prompt", Scope: "once"}
	if destination != nil {
		decision.HostFingerprint = destination.HostKey
		decision.User = destination.User
	}
	defer func() {
		decision.Outcome = "denied"
		if allowed {
			decision.Outcome = "approved"
		}
		if resultErr != nil {
			decision.Outcome = "error"
		}
		if ctx.Err() != nil {
			decision.Outcome = "cancelled"
		}
		if a.observe != nil {
			a.observe(decision)
		}
	}()
	select {
	case a.gate <- struct{}{}:
		defer func() { <-a.gate }()
	case <-ctx.Done():
		return false, ctx.Err()
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if fingerprint == "" {
		return false, fmt.Errorf("missing signing key identity")
	}
	// Who is asking is read for every request, answered from cache or not:
	// it costs microseconds, and it decides which decision applies.
	live := ancestry(caller)
	boundary, anchored := live.Boundary(a.now())
	req := ui.ConfirmRequest{Title: "Allow SSH key use?", Message: clean(comment) + "\nKey: " + fingerprint}
	if destination == nil || destination.HostKey == "" || destination.User == "" {
		// Knowing who is asking is not knowing where the signature is going.
		req.Message += "\n\nDestination not verified. This approval applies to one signature only."
		// Who is asking is still worth seeing; where a decision would attach
		// is not, because no decision is on offer for one signature.
		req.Chain, _ = displayed(live, boundary, anchored)
		allowed, err := a.dialogs.Confirm(ctx, req)
		if ctx.Err() != nil {
			return false, ctx.Err()
		}
		return allowed, err
	}
	broad := grantKey{fingerprint, destination.HostKey, destination.User, ""}
	anchoredKeys := anchorKeys(fingerprint, destination, live, boundary, anchored)
	// A refusal anywhere in the ancestry is consulted first and outranks every
	// approval below it: a refusal drawn at a window means nothing started from
	// that window is signed for, or "stop asking me from here" says nothing.
	// An approval stored broadly belongs to callers with no ancestry of their
	// own, and is not lent to the ones that have it.
	for _, key := range anchoredKeys {
		if cached, ok := a.decisions.lookup(key); ok && !cached.allowed {
			return recall(&decision, cached), nil
		}
	}
	if cached, ok := a.decisions.lookup(broad); ok && !anchored {
		return recall(&decision, cached), nil
	}
	for _, key := range anchoredKeys {
		if cached, ok := a.decisions.lookup(key); ok {
			return recall(&decision, cached), nil
		}
	}
	name := clean(destination.Host)
	if name == "" {
		name = "server name unavailable"
	}
	req.Destination = clean(destination.User) + " @ " + name
	req.Message += "\nServer identity: " + destination.HostKey
	req.Chain, req.Boundary = displayed(live, boundary, anchored)
	scoped, ok := a.dialogs.(ui.ScopedDialogs)
	if !ok {
		allowed, err := a.dialogs.Confirm(ctx, req)
		if ctx.Err() != nil {
			return false, ctx.Err()
		}
		return allowed, err
	}
	answer, err := scoped.ConfirmScoped(ctx, req)
	decision.Scope = string(answer.Scope)
	// A late UI answer must never create a lease after the client disappears.
	if ctx.Err() != nil {
		return false, ctx.Err()
	}
	if err != nil {
		a.decisions.forget(broad)
		for _, key := range anchoredKeys {
			a.decisions.forget(key)
		}
		return false, err
	}
	key, link, remember := broad, proc.Link{}, true
	switch {
	case !anchored:
		// Nobody could be named. An approval may still be kept for every
		// program on this Mac, because the user asked for that and can see it
		// in the window; a refusal may not, because it would be enforced on
		// everything afterwards without showing anything at all.
		remember = answer.Allowed
	default:
		at := boundary
		// The user may widen the decision to an ancestor further up the
		// chain. Below the proposed link there is nothing durable to hold
		// it, so that direction is not offered and not accepted.
		if answer.Boundary > boundary && answer.Boundary < len(live.Links) {
			at = answer.Boundary
		}
		// Read the ancestry again. The user had as long as they liked to
		// answer, and their signature is still theirs to allow, but a
		// decision is never stored against a chain they were not shown.
		if ancestry(caller).Fingerprint() != live.Fingerprint() {
			remember = false
			break
		}
		key.anchor = live.Anchor(at).Fingerprint()
		link = live.Links[at]
	}
	if answer.Scope.IsProcessLifetime() && key.anchor == "" {
		// A lifetime measured against a process nobody could name.
		remember = false
	}
	if !remember {
		// The answer is still checked even though nothing is kept: an
		// impossible duration is a broken helper, and a broken helper is
		// refused rather than quietly downgraded to a single signature.
		if _, _, err := answer.Lifetime(); err != nil {
			return false, err
		}
		decision.Scope = "once"
		return answer.Allowed, nil
	}
	decision.Process, decision.ProcessPID, decision.ProcessVersion = clean(link.Display()), link.PID, link.Version
	until, err := a.decisions.remember(key, destination.Host, link, answer)
	if err != nil {
		return false, err
	}
	if !until.IsZero() {
		decision.ExpiresAt = &until
	}
	return answer.Allowed, nil
}

// anchorKeys names every decision that may answer this request: the one made
// for the boundary link, and the ones made for its ancestors. A program that
// was trusted covers the programs it starts, which is the point of trusting
// it; below the boundary there is nothing that outlives the request itself.
func anchorKeys(fingerprint string, destination *Destination, live proc.Chain, boundary int, anchored bool) []grantKey {
	if !anchored {
		return nil
	}
	keys := make([]grantKey, 0, len(live.Links)-boundary)
	for i := boundary; i < len(live.Links); i++ {
		keys = append(keys, grantKey{fingerprint, destination.HostKey, destination.User, live.Anchor(i).Fingerprint()})
	}
	return keys
}

func recall(decision *Decision, cached temporaryDecision) bool {
	decision.Source = "cached"
	decision.ExpiresAt = &cached.expires
	decision.Scope = "timed-denial"
	if cached.allowed {
		decision.Scope = "timed-approval"
	}
	decision.Process, decision.ProcessPID, decision.ProcessVersion = cached.anchorName(), cached.anchor.PID, cached.anchor.Version
	return cached.allowed
}

func ancestry(caller Caller) proc.Chain {
	if caller == nil {
		return proc.Chain{}
	}
	return caller()
}

// displayed renders the chain for the dialog. Signing identities are read here
// and nowhere else: they cost orders of magnitude more than the process table,
// and only someone looking at a dialog has any use for them. A zero boundary
// means no ancestor could be named, so no timed decision is on offer.
func displayed(c proc.Chain, boundary int, anchored bool) ([]ui.ProcessLink, int) {
	if c.Empty() {
		return nil, 0
	}
	described := proc.Describe(c)
	links := make([]ui.ProcessLink, len(described.Links))
	for i, l := range described.Links {
		links[i] = ui.ProcessLink{Name: clean(l.Display()), PID: l.PID, Team: clean(l.Team), Verified: l.Verified}
	}
	if !anchored {
		return links, 0
	}
	return links, boundary
}

func clean(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.In(r, unicode.Cf) {
			return ' '
		}
		return r
	}, s)
}
