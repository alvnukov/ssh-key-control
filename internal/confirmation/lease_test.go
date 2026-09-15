package confirmation_test

import (
	"context"
	"testing"
	"time"

	"github.com/alvnukov/ssh-key-control/internal/confirmation"
	"github.com/alvnukov/ssh-key-control/internal/ui"
)

type scopedDialogs struct {
	dialogs
	scope ui.GrantScope
	calls int
}

func (d *scopedDialogs) ConfirmScoped(_ context.Context, _ ui.ConfirmRequest) (ui.Confirmation, error) {
	d.calls++
	return ui.Confirmation{Allowed: d.allowed, Scope: d.scope}, d.err
}
func TestExplicitGrants(t *testing.T) {
	for _, scope := range []ui.GrantScope{ui.GrantOnce, ui.Grant5Minutes, ui.Grant15Minutes, ui.GrantDay} {
		t.Run(string(scope), func(t *testing.T) {
			now := time.Date(2026, 9, 11, 23, 50, 0, 0, time.FixedZone("local", 3*3600))
			d := &scopedDialogs{dialogs: dialogs{allowed: true}, scope: scope}
			a := confirmation.New(d, func() time.Time { return now })
			target := &confirmation.Destination{Host: "host", User: "alice", HostKey: "SHA256:server"}
			check := func(key string, dest *confirmation.Destination) {
				t.Helper()
				if allowed, err := a.Authorize(context.Background(), key, "key comment", dest, nil); err != nil || !allowed {
					t.Fatalf("Authorize: %t %v", allowed, err)
				}
			}
			check("SHA256:key", target)
			check("SHA256:key", target)
			want := 1
			if scope == ui.GrantOnce {
				want = 2
			}
			if d.calls != want {
				t.Fatalf("got %d dialogs, want %d", d.calls, want)
			}
			check("SHA256:other-key", target)
			other := *target
			other.User = "root"
			check("SHA256:key", &other)
			other = *target
			other.HostKey = "SHA256:other-server"
			check("SHA256:key", &other)
			if d.calls != want+3 {
				t.Fatal("approval leaked across keys, users or servers")
			}
			check("SHA256:key", nil)
			if len(d.requests) != 1 {
				t.Fatal("unknown destination reused an approval")
			}
			switch scope {
			case ui.Grant5Minutes:
				now = now.Add(5 * time.Minute)
			case ui.Grant15Minutes:
				now = now.Add(15 * time.Minute)
			case ui.GrantDay:
				now = time.Date(2026, 9, 12, 0, 0, 0, 0, now.Location())
			}
			check("SHA256:key", target)
			if d.calls != want+4 {
				t.Fatal("expired approval reused")
			}
		})
	}
}
func TestDeniedOrInvalidGrantNeverCaches(t *testing.T) {
	for _, allowed := range []bool{false, true} {
		d := &scopedDialogs{dialogs: dialogs{allowed: allowed}, scope: "invalid"}
		a := confirmation.New(d, time.Now)
		for range 2 {
			ok, _ := a.Authorize(context.Background(), "SHA256:key", "", &confirmation.Destination{User: "u", HostKey: "SHA256:server"}, nil)
			if ok {
				t.Fatal("denied or invalid choice authorized signing")
			}
		}
		if d.calls != 2 {
			t.Fatal("denial was cached as permission")
		}
	}
}
func TestDayGrantUsesCalendarMidnight(t *testing.T) {
	location, err := time.LoadLocation("America/New_York")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 3, 8, 0, 30, 0, 0, location)
	d := &scopedDialogs{dialogs: dialogs{allowed: true}, scope: ui.GrantDay}
	a := confirmation.New(d, func() time.Time { return now })
	target := &confirmation.Destination{User: "u", HostKey: "SHA256:server"}
	a.Authorize(context.Background(), "SHA256:key", "", target, nil)
	now = time.Date(2026, 3, 8, 23, 59, 59, 0, location)
	a.Authorize(context.Background(), "SHA256:key", "", target, nil)
	if d.calls != 1 {
		t.Fatal("day grant expired before local midnight")
	}
	now = now.Add(time.Second)
	a.Authorize(context.Background(), "SHA256:key", "", target, nil)
	if d.calls != 2 {
		t.Fatal("day grant survived DST midnight")
	}
}

func TestDenyDurationsSilenceRepeatPrompts(t *testing.T) {
	for _, tc := range []struct {
		scope ui.GrantScope
		wait  time.Duration
	}{
		{ui.Deny5Minutes, 5 * time.Minute},
		{ui.Deny1Hour, time.Hour},
	} {
		t.Run(string(tc.scope), func(t *testing.T) {
			now := time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)
			d := &scopedDialogs{dialogs: dialogs{allowed: false}, scope: tc.scope}
			a := confirmation.New(d, func() time.Time { return now })
			target := &confirmation.Destination{Host: "host", User: "alice", HostKey: "SHA256:server"}
			// The refusal is kept for the shell that asked, so the repeats
			// have to come from that same shell to be answered from it.
			who := caller(session(firstTestPID, firstTestPID+1))
			if ok, err := a.Authorize(context.Background(), "SHA256:key", "", target, who); err != nil || ok {
				t.Fatalf("first deny: %t %v", ok, err)
			}
			for range 2 {
				ok, err := a.Authorize(context.Background(), "SHA256:key", "", target, who)
				if err != nil || ok {
					t.Fatalf("during lease: %t %v", ok, err)
				}
			}
			if d.calls != 1 {
				t.Fatalf("got %d dialogs, want 1 while the denial lease is active", d.calls)
			}
			other := *target
			other.User = "root"
			a.Authorize(context.Background(), "SHA256:key", "", &other, who)
			other = *target
			other.HostKey = "SHA256:other-server"
			a.Authorize(context.Background(), "SHA256:key", "", &other, who)
			a.Authorize(context.Background(), "SHA256:other-key", "", target, nil)
			if d.calls != 4 {
				t.Fatalf("denial leaked across keys, users or servers: %d dialogs", d.calls)
			}
			now = now.Add(tc.wait)
			ok, err := a.Authorize(context.Background(), "SHA256:key", "", target, nil)
			if err != nil || ok {
				t.Fatalf("after expiry: %t %v", ok, err)
			}
			if d.calls != 5 {
				t.Fatal("expired denial still silenced prompts")
			}
		})
	}
}

func TestPlainDenyAndUnverifiedDestinationNeverSilence(t *testing.T) {
	d := &scopedDialogs{dialogs: dialogs{allowed: false}, scope: ui.GrantOnce}
	a := confirmation.New(d, time.Now)
	target := &confirmation.Destination{Host: "host", User: "alice", HostKey: "SHA256:server"}
	for range 2 {
		if ok, err := a.Authorize(context.Background(), "SHA256:key", "", target, nil); err != nil || ok {
			t.Fatalf("plain deny: %t %v", ok, err)
		}
	}
	if d.calls != 2 {
		t.Fatal("plain denial was remembered")
	}
	for range 2 {
		if ok, err := a.Authorize(context.Background(), "SHA256:key", "", nil, nil); err != nil || ok {
			t.Fatalf("unverified deny: %t %v", ok, err)
		}
	}
	if len(d.requests) != 2 {
		t.Fatal("unverified destination was silenced")
	}
}
