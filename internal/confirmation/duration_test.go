package confirmation_test

import (
	"context"
	"math"
	"testing"
	"time"

	"github.com/alvnukov/ssh-key-control/internal/confirmation"
	"github.com/alvnukov/ssh-key-control/internal/ui"
)

type durationDialogs struct {
	dialogs
	choice ui.Confirmation
	calls  int
}

func (d *durationDialogs) ConfirmScoped(context.Context, ui.ConfirmRequest) (ui.Confirmation, error) {
	d.calls++
	return d.choice, nil
}

func TestSymmetricDurationsExpireAndStayBoundToExactTuple(t *testing.T) {
	loc, err := time.LoadLocation("America/New_York")
	if err != nil {
		t.Fatal(err)
	}
	for _, allowed := range []bool{false, true} {
		for _, tc := range []struct {
			allow, deny ui.GrantScope
			minutes     int
			duration    time.Duration
			day         bool
		}{
			{ui.Grant5Minutes, ui.Deny5Minutes, 0, 5 * time.Minute, false},
			{ui.Grant15Minutes, ui.Deny15Minutes, 0, 15 * time.Minute, false},
			{ui.GrantDay, ui.DenyDay, 0, 0, true},
			{ui.GrantCustom, ui.DenyCustom, 1, time.Minute, false},
			{ui.GrantCustom, ui.DenyCustom, 1440, 24 * time.Hour, false},
		} {
			now := time.Date(2026, 3, 8, 0, 30, 0, 0, loc) // DST day is not 24 hours.
			scope := tc.deny
			if allowed {
				scope = tc.allow
			}
			d := &durationDialogs{dialogs: dialogs{allowed: allowed}, choice: ui.Confirmation{Allowed: allowed, Scope: scope, DurationMinutes: tc.minutes}}
			a := confirmation.New(d, func() time.Time { return now })
			target := &confirmation.Destination{Host: "host", User: "alice", HostKey: "SHA256:host"}
			check := func(key string, dest *confirmation.Destination) {
				t.Helper()
				got, e := a.Authorize(context.Background(), key, "", dest)
				if e != nil || got != allowed {
					t.Fatalf("%+v: got %v %v", d.choice, got, e)
				}
			}
			check("SHA256:key", target)
			check("SHA256:key", target)
			if d.calls != 1 {
				t.Fatal("duration did not cache exact tuple")
			}
			other := *target
			other.User = "root"
			check("SHA256:key", &other)
			other = *target
			other.HostKey = "SHA256:other"
			check("SHA256:key", &other)
			check("SHA256:other", target)
			if d.calls != 4 {
				t.Fatal("duration crossed key/user/hostkey boundary")
			}
			until := now.Add(tc.duration)
			if tc.day {
				until = time.Date(2026, 3, 9, 0, 0, 0, 0, loc)
			}
			now = until.Add(-time.Nanosecond)
			check("SHA256:key", target)
			if d.calls != 4 {
				t.Fatal("duration expired early")
			}
			now = until
			check("SHA256:key", target)
			if d.calls != 5 {
				t.Fatal("duration survived expiry")
			}
			check("SHA256:key", nil)
			check("SHA256:key", nil)
			if len(d.requests) != 2 || d.calls != 5 {
				t.Fatal("unverified destination reused duration")
			}
		}
	}
}

func TestInvalidCustomDurationNeverCreatesLease(t *testing.T) {
	for _, allowed := range []bool{false, true} {
		scope := ui.DenyCustom
		if allowed {
			scope = ui.GrantCustom
		}
		for _, minutes := range []int{-1, 0, 1441, math.MaxInt} {
			d := &durationDialogs{choice: ui.Confirmation{Allowed: allowed, Scope: scope, DurationMinutes: minutes}}
			a := confirmation.New(d, time.Now)
			for range 2 {
				got, err := a.Authorize(context.Background(), "SHA256:key", "", &confirmation.Destination{User: "alice", HostKey: "SHA256:host"})
				if got || err == nil {
					t.Fatalf("invalid duration accepted: %+v %v", d.choice, err)
				}
			}
			if d.calls != 2 {
				t.Fatal("invalid duration cached")
			}
		}
	}
}
