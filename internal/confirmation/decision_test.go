package confirmation_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/alvnukov/ssh-key-control/internal/confirmation"
	"github.com/alvnukov/ssh-key-control/internal/ui"
)

func TestObservedDecisionsDistinguishCachedApprovalWithoutSecrets(t *testing.T) {
	d := &scopedDialogs{dialogs: dialogs{allowed: true}, scope: ui.Grant5Minutes}
	var events []confirmation.Decision
	a := confirmation.NewWithObserver(d, nil, func(e confirmation.Decision) { events = append(events, e) })
	dest := &confirmation.Destination{Host: "display-name", User: "alice", HostKey: "SHA256:host"}
	for range 2 {
		if ok, err := a.Authorize(context.Background(), "SHA256:key", "private-comment-must-not-be-logged", dest, nil); !ok || err != nil {
			t.Fatal(ok, err)
		}
	}
	if len(events) != 2 || events[0].Source != "prompt" || events[1].Source != "cached" {
		t.Fatal(events)
	}
	for _, e := range events {
		if e.KeyFingerprint != "SHA256:key" || e.HostFingerprint != "SHA256:host" || e.User != "alice" || e.Outcome != "approved" || e.ExpiresAt == nil {
			t.Fatalf("incomplete event %+v", e)
		}
	}
	b, _ := json.Marshal(events)
	if strings.Contains(string(b), "private-comment") {
		t.Fatal("comment leaked")
	}
	if ok, err := a.Authorize(context.Background(), "SHA256:key", "", nil, nil); !ok || err != nil {
		t.Fatal(ok, err)
	}
	if events[2].Source != "prompt" || events[2].HostFingerprint != "" {
		t.Fatal("generic request reused remembered scope")
	}
}
func TestCancelledDecisionIsRecordedAsCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var got confirmation.Decision
	a := confirmation.NewWithObserver(&dialogs{}, nil, func(e confirmation.Decision) { got = e })
	if ok, _ := a.Authorize(ctx, "key", "", nil, nil); ok {
		t.Fatal("cancelled request approved")
	}
	if got.Outcome != "cancelled" {
		t.Fatal(got)
	}
}
