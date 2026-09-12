package helper

import (
	"context"
	"fmt"
	"testing"

	"github.com/alvnukov/ssh-key-control/internal/ui"
)

func TestCustomDurationWireBoundsAndDirections(t *testing.T) {
	c := start(t)
	for _, allowed := range []bool{false, true} {
		answer, scope := "no", ui.DenyCustom
		if allowed {
			answer, scope = "yes", ui.GrantCustom
		}
		for _, minutes := range []int{1, 1440} {
			wire := fmt.Sprintf("{\"ok\":true,\"answer\":%q,\"scope\":%q,\"durationMinutes\":%d}", answer, scope, minutes)
			got, err := c.ConfirmScoped(context.Background(), ui.ConfirmRequest{Title: "raw response", Message: wire, Destination: "alice @ server"})
			if err != nil || got != (ui.Confirmation{Allowed: allowed, Scope: scope, DurationMinutes: minutes}) {
				t.Fatalf("valid custom %s = %+v, %v", wire, got, err)
			}
		}
		for _, minutes := range []string{"0", "-1", "1441", "1.5", "1.0", "1e3", "1e9999", "9223372036854775808", "\"10\"", "null", "NaN", "Infinity"} {
			wire := fmt.Sprintf("{\"ok\":true,\"answer\":%q,\"scope\":%q,\"durationMinutes\":%s}", answer, scope, minutes)
			got, err := c.ConfirmScoped(context.Background(), ui.ConfirmRequest{Title: "raw response", Message: wire, Destination: "alice @ server"})
			if err == nil || got != (ui.Confirmation{}) {
				t.Fatalf("accepted invalid custom %s: %+v %v", wire, got, err)
			}
		}
	}
}

func TestDurationWireRejectsExtraFieldsMismatchesAndUnverifiedDestination(t *testing.T) {
	c := start(t)
	wires := []string{
		`{"ok":true,"answer":"yes","scope":"custom"}`,
		`{"ok":true,"answer":"yes","scope":"denycustom","durationMinutes":1}`,
		`{"ok":true,"answer":"no","scope":"custom","durationMinutes":1}`,
		`{"ok":true,"answer":"yes","scope":"once","durationMinutes":0}`,
		`{"ok":true,"answer":"yes","scope":"15m","durationMinutes":null}`,
		`{"ok":true,"answer":"yes","durationMinutes":1}`,
		`{"ok":true,"answer":"yes","scope":"custom","durationMinutes":1,"unrecognized":true}`,
		`{"ok":true,"answer":"maybe","scope":"denycustom","durationMinutes":1}`,
		`{"ok":true,"answer":"yes","scope":"forever","durationMinutes":1}`,
	}
	for _, wire := range wires {
		got, err := c.ConfirmScoped(context.Background(), ui.ConfirmRequest{Title: "raw response", Message: wire, Destination: "alice @ server"})
		if err == nil || got != (ui.Confirmation{}) {
			t.Fatalf("accepted invalid response %s: %+v %v", wire, got, err)
		}
	}
	for _, wire := range []string{
		`{"ok":true,"answer":"yes","scope":"custom","durationMinutes":1}`,
		`{"ok":true,"answer":"no","scope":"denycustom","durationMinutes":1}`,
		`{"ok":true,"answer":"no","scope":"deny15m"}`,
		`{"ok":true,"answer":"no","scope":"denyday"}`,
	} {
		got, err := c.ConfirmScoped(context.Background(), ui.ConfirmRequest{Title: "raw response", Message: wire})
		if err == nil || got != (ui.Confirmation{}) {
			t.Fatalf("unverified timed response accepted: %+v %v", got, err)
		}
		if _, err := c.call(request{Op: "secret", Title: "raw response", Message: wire}); err == nil {
			t.Fatal("duration accepted on secret response")
		}
	}
}

func TestNewBuiltinDenyScopesAreRecognized(t *testing.T) {
	c := start(t)
	for _, scope := range []ui.GrantScope{ui.Deny15Minutes, ui.DenyDay} {
		wire := fmt.Sprintf("{\"ok\":true,\"answer\":\"no\",\"scope\":%q}", scope)
		got, err := c.ConfirmScoped(context.Background(), ui.ConfirmRequest{Title: "raw response", Message: wire, Destination: "alice @ server"})
		if err != nil || got != (ui.Confirmation{Scope: scope}) {
			t.Fatalf("deny %s = %+v %v", scope, got, err)
		}
	}
}
