package helper

import (
	"context"
	"testing"

	"github.com/alvnukov/ssh-key-control/internal/ui"
)

func TestConfirmScopedFailsClosed(t *testing.T) {
	c := start(t)
	for _, req := range []ui.ConfirmRequest{
		{Title: "scoped", Destination: "alice@production", Message: "forever"},
		{Title: "forced scope", Message: "5m"},
		{Title: "deny me", Message: "day"},
		{Title: "empty scope", Destination: "alice@production"},
	} {
		answer, err := c.ConfirmScoped(context.Background(), req)
		if err == nil || answer.Allowed || answer.Scope != "" {
			t.Errorf("request %+v: got %+v, %v; want closed failure", req, answer, err)
		}
	}
}

func TestScopeNotValidForSecrets(t *testing.T) {
	c := start(t)
	answer, err := c.Secret(context.Background(), ui.SecretRequest{Title: "unexpected scope"})
	if err == nil || answer.Secret != "" {
		t.Fatalf("Secret = %+v, %v; want protocol failure", answer, err)
	}
}

func TestLegacyConfirmNeverOffersTimedChoice(t *testing.T) {
	c := start(t)
	allowed, err := c.Confirm(context.Background(), ui.ConfirmRequest{Title: "legacy", Destination: "alice@production"})
	if err != nil || !allowed {
		t.Fatalf("legacy Confirm = %v, %v", allowed, err)
	}
}

func TestUnknownDestinationAlwaysAsksOnce(t *testing.T) {
	c := start(t)
	for i := 0; i < 2; i++ {
		answer, err := c.ConfirmScoped(context.Background(), ui.ConfirmRequest{Title: "allow me"})
		if err != nil || answer != (ui.Confirmation{Allowed: true, Scope: ui.GrantOnce}) {
			t.Fatalf("ConfirmScoped = %+v, %v", answer, err)
		}
	}
}

func TestVerifiedOneShotDestinationOnHelperWire(t *testing.T) {
	c := start(t)
	answer, err := c.ConfirmScoped(context.Background(), ui.ConfirmRequest{Title: "forwarded once", Destination: "alice@production", OnceOnly: true})
	if err != nil || answer != (ui.Confirmation{Allowed: true, Scope: ui.GrantOnce}) {
		t.Fatalf("verified one-shot wire: %+v %v", answer, err)
	}
	for _, scope := range []string{"5m", "day", "process", "deny5m"} {
		answer, err := c.ConfirmScoped(context.Background(), ui.ConfirmRequest{Title: "forced scope", Message: scope, Destination: "alice@production", OnceOnly: true})
		if err == nil || answer.Allowed {
			t.Fatalf("legacy timed answer accepted for once-only: %s %+v %v", scope, answer, err)
		}
	}
}
