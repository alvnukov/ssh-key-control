// Package confirmation owns explicit, in-memory approvals for agent signatures.
package confirmation

import (
	"context"
	"fmt"
	"strings"
	"time"
	"unicode"

	"github.com/alvnukov/ssh-key-control/internal/ui"
)

// Destination comes only from a verified SSH session binding and the signed
// user-authentication payload. Host is a display label, not proof of identity.
// HostKey, not a caller-supplied hostname, identifies the server.
type Destination struct {
	Host, User, HostKey string
}

type grantKey struct{ key, server, user string }

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
func (a *Authorizer) Authorize(ctx context.Context, fingerprint, comment string, destination *Destination) (allowed bool, resultErr error) {
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
	req := ui.ConfirmRequest{Title: "Allow SSH key use?", Message: clean(comment) + "\nKey: " + fingerprint}
	if destination == nil || destination.HostKey == "" || destination.User == "" {
		req.Message += "\n\nDestination not verified. This approval applies to one signature only."
		allowed, err := a.dialogs.Confirm(ctx, req)
		if ctx.Err() != nil {
			return false, ctx.Err()
		}
		return allowed, err
	}
	key := grantKey{fingerprint, destination.HostKey, destination.User}
	if cached, ok := a.decisions.lookup(key); ok {
		decision.Source = "cached"
		decision.ExpiresAt = &cached.expires
		decision.Scope = "timed-denial"
		if cached.allowed {
			decision.Scope = "timed-approval"
		}
		return cached.allowed, nil
	}
	name := clean(destination.Host)
	if name == "" {
		name = "server name unavailable"
	}
	req.Destination = clean(destination.User) + " @ " + name
	req.Message += "\nServer identity: " + destination.HostKey
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
		a.decisions.forget(key)
		return false, err
	}
	until, err := a.decisions.remember(key, destination.Host, answer)
	if err != nil {
		return false, err
	}
	if !until.IsZero() {
		decision.ExpiresAt = &until
	}
	return answer.Allowed, nil
}

func clean(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.In(r, unicode.Cf) {
			return ' '
		}
		return r
	}, s)
}
