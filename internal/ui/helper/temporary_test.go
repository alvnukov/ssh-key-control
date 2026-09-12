package helper

import (
	"context"
	"github.com/alvnukov/ssh-key-control/internal/ui"
	"testing"
)

func TestConfirmationRejectsManagementActions(t *testing.T) {
	c := start(t)
	for _, wire := range []string{
		`{"ok":true,"answer":"yes","change":{"action":"update","id":"id","minutes":15}}`,
		`{"ok":true,"answer":"no","change":{"action":"revoke","id":"id"}}`,
	} {
		if _, err := c.ConfirmScoped(context.Background(), ui.ConfirmRequest{Title: "raw response", Message: wire, Destination: "u @ host"}); err == nil {
			t.Fatal("confirmation accepted management action")
		}
	}
}
