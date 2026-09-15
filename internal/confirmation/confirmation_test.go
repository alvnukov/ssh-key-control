package confirmation_test

import (
	"context"
	"testing"
	"time"

	"github.com/alvnukov/ssh-key-control/internal/confirmation"
	"github.com/alvnukov/ssh-key-control/internal/ui"
)

type dialogs struct {
	ui.Dialogs
	requests []ui.ConfirmRequest
	allowed  bool
	err      error
}

func (d *dialogs) Confirm(_ context.Context, req ui.ConfirmRequest) (bool, error) {
	d.requests = append(d.requests, req)
	return d.allowed, d.err
}

func TestGenericApprovalPromptsEveryTime(t *testing.T) {
	d := &dialogs{allowed: true}
	a := confirmation.New(d, func() time.Time { return time.Unix(0, 0) })
	for range 2 {
		allowed, err := a.Authorize(context.Background(), "SHA256:key", "work", nil, nil)
		if err != nil || !allowed {
			t.Fatalf("Authorize = %v, %v", allowed, err)
		}
	}
	if len(d.requests) != 2 {
		t.Fatalf("got %d prompts, want 2", len(d.requests))
	}
}
