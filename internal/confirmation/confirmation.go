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
	observe func(Decision)
	gate    chan struct{}
	dialogs Dialogs
	now     func() time.Time
	grants  map[grantKey]time.Time
	denials map[grantKey]time.Time
}

func New(dialogs Dialogs, now func() time.Time) *Authorizer {
	return NewWithObserver(dialogs, now, nil)
}

// NewWithObserver records decisions after releasing the dialog queue.
func NewWithObserver(dialogs Dialogs, now func() time.Time, observe func(Decision)) *Authorizer {
	if now == nil {
		now = time.Now
	}
	return &Authorizer{observe: observe, gate: make(chan struct{}, 1), dialogs: dialogs, now: now, grants: make(map[grantKey]time.Time), denials: make(map[grantKey]time.Time)}
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
	now := a.now()
	for k, expires := range a.grants {
		if !now.Before(expires) {
			delete(a.grants, k)
		}
	}
	for k, until := range a.denials {
		if !now.Before(until) {
			delete(a.denials, k)
		}
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
	// A standing refusal silences the prompt entirely, exactly as a grant
	// would have authorized it silently.
	if until, ok := a.denials[key]; ok && now.Before(until) {
		decision.Source = "cached"
		decision.ExpiresAt = &until
		decision.Scope = "timed-denial"
		return false, nil
	}
	if expires, ok := a.grants[key]; ok && now.Before(expires) {
		decision.Source = "cached"
		decision.ExpiresAt = &expires
		decision.Scope = "timed-approval"
		return true, nil
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
	if err != nil || !answer.Allowed {
		delete(a.grants, key)
		if err != nil {
			return false, err
		}
		now = a.now() // Lease starts when the user answers, not when the dialog opened.
		switch answer.Scope {
		case "", ui.GrantOnce:
			delete(a.denials, key) // A plain denial refuses once, nothing more.
		case ui.Deny5Minutes:
			a.denials[key] = now.Add(5 * time.Minute)
		case ui.Deny1Hour:
			a.denials[key] = now.Add(time.Hour)
		default:
			return false, fmt.Errorf("unsupported denial duration %q", answer.Scope)
		}
		if until, ok := a.denials[key]; ok {
			decision.ExpiresAt = &until
		}
		return false, nil
	}
	delete(a.denials, key) // A later approval supersedes any refusal.
	// Start a lease when the user approves, not when the dialog opened.
	now = a.now()
	var until time.Time
	switch answer.Scope {
	case "", ui.GrantOnce:
		return true, nil
	case ui.Grant5Minutes:
		until = now.Add(5 * time.Minute)
	case ui.Grant15Minutes:
		until = now.Add(15 * time.Minute)
	case ui.GrantDay:
		y, m, d := now.Date()
		until = time.Date(y, m, d+1, 0, 0, 0, 0, now.Location())
	default:
		return false, fmt.Errorf("unsupported approval duration %q", answer.Scope)
	}
	decision.ExpiresAt = &until
	a.grants[key] = until
	return true, nil
}

func clean(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.In(r, unicode.Cf) {
			return ' '
		}
		return r
	}, s)
}
