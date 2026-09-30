package confirmation

import (
	"context"
	"errors"
	"strings"

	"github.com/alvnukov/ssh-key-control/internal/ui"
)

// AuthorizeForwarded never reads or writes temporary decisions. Verified SSH
// sessions identify hosts, but do not attest the remote process using the key.
func (a *Authorizer) AuthorizeForwarded(ctx context.Context, fingerprint, comment string, destination *Destination, hops []string) (allowed bool, resultErr error) {
	decision := Decision{KeyFingerprint: fingerprint, Source: "prompt", Scope: "once"}
	if destination != nil {
		decision.HostFingerprint, decision.User = destination.HostKey, destination.User
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
	if fingerprint == "" || destination == nil || destination.User == "" || destination.HostKey == "" || len(hops) == 0 {
		return false, errors.New("missing forwarded signing identity")
	}
	name := clean(destination.Host)
	if name == "" {
		name = "server name unavailable"
	}
	message := clean(comment) + "\nKey: " + fingerprint + "\nServer identity: " + destination.HostKey
	message += "\nForwarded SSH request. Allow or deny this signature once; timed decisions are unavailable."
	message += "\nThe remote process is not attested. The local SSH process owns only the forwarding tunnel."
	message += "\nVerified forwarding-hop fingerprints: " + clean(strings.Join(hops, " -> "))
	req := ui.ConfirmRequest{Title: "Allow SSH key use?", Message: message,
		Destination: clean(destination.User) + " @ " + name, OnceOnly: true}
	dialogs, ok := a.dialogs.(ui.ScopedDialogs)
	if !ok {
		return false, errors.New("one-shot destination confirmation unavailable")
	}
	answer, err := dialogs.ConfirmScoped(ctx, req)
	if ctx.Err() != nil {
		return false, ctx.Err()
	}
	if err != nil {
		return false, err
	}
	if answer.Scope != ui.GrantOnce || answer.DurationMinutes != 0 || answer.Boundary != 0 {
		return false, errors.New("forwarded confirmation must apply to one signature")
	}
	return answer.Allowed, nil
}
