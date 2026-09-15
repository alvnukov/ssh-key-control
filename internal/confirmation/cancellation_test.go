package confirmation_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/alvnukov/ssh-key-control/internal/confirmation"
	"github.com/alvnukov/ssh-key-control/internal/ui"
)

type blockingDialogs struct {
	entered chan struct{}
	release chan struct{}
	calls   int
	cancel  context.CancelFunc
}

func (d *blockingDialogs) Confirm(ctx context.Context, r ui.ConfirmRequest) (bool, error) {
	answer, err := d.ConfirmScoped(ctx, r)
	return answer.Allowed, err
}
func (d *blockingDialogs) ConfirmScoped(context.Context, ui.ConfirmRequest) (ui.Confirmation, error) {
	d.calls++
	if d.entered != nil {
		close(d.entered)
		<-d.release
	}
	if d.cancel != nil {
		d.cancel()
	}
	return ui.Confirmation{Allowed: true, Scope: ui.Grant5Minutes}, nil
}

func TestQueuedApprovalCanBeCancelled(t *testing.T) {
	d := &blockingDialogs{entered: make(chan struct{}), release: make(chan struct{})}
	a := confirmation.New(d, nil)
	first := make(chan struct{})
	go func() { defer close(first); a.Authorize(context.Background(), "key", "", nil, nil) }()
	<-d.entered
	defer func() { close(d.release); <-first }()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, err := a.Authorize(ctx, "other", "", nil, nil); done <- err }()
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("queued cancellation: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancelled request waited for another client's dialog")
	}
}

func TestCancelledAnswerCannotCreateGrant(t *testing.T) {
	for _, scoped := range []bool{false, true} {
		ctx, cancel := context.WithCancel(context.Background())
		d := &blockingDialogs{cancel: cancel}
		a := confirmation.New(d, nil)
		var dest *confirmation.Destination
		if scoped {
			dest = &confirmation.Destination{User: "alice", HostKey: "SHA256:server"}
		}
		allowed, err := a.Authorize(ctx, "key", "", dest, nil)
		if allowed || !errors.Is(err, context.Canceled) {
			t.Fatalf("cancelled answer: %t %v", allowed, err)
		}
		d.cancel = nil
		if ok, err := a.Authorize(context.Background(), "key", "", dest, nil); !ok || err != nil {
			t.Fatalf("next answer: %t %v", ok, err)
		}
		if d.calls != 2 {
			t.Fatal("cancelled answer created a reusable grant")
		}
	}
}
