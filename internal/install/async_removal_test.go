package install

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/alvnukov/ssh-key-control/internal/agent"
	"github.com/alvnukov/ssh-key-control/internal/launchd"
	"github.com/alvnukov/ssh-key-control/internal/launchd/launchdtest"
)

// launchd can acknowledge bootout with EINPROGRESS while the old label is
// retained. Bootstrap must not run until print confirms removal of both labels.
type removingLaunchd struct {
	base       *launchdtest.Fake
	remaining  map[string]int
	printError error
	onPrint    func()
	early      bool
}

func (r *removingLaunchd) Run(ctx context.Context, args ...string) (string, error) {
	if args[0] == "bootout" {
		label := strings.TrimPrefix(args[1], "gui/501/")
		if _, ok := r.base.Loaded[label]; ok {
			r.base.Calls = append(r.base.Calls, strings.Join(args, " "))
			return "", &launchd.ExitError{Args: args, Code: 36, Output: "Operation now in progress"}
		}
	}
	if args[0] == "print" {
		label := strings.TrimPrefix(args[1], "gui/501/")
		if left, removing := r.remaining[label]; removing {
			if r.onPrint != nil {
				r.onPrint()
			}
			if r.printError != nil {
				return "", r.printError
			}
			if left == 0 {
				delete(r.remaining, label)
				delete(r.base.Loaded, label)
			} else {
				r.remaining[label]--
			}
		}
	}
	if args[0] == "bootstrap" && len(r.remaining) != 0 {
		r.early = true
		return "", errors.New("bootstrap before confirmed removal")
	}
	return r.base.Run(ctx, args...)
}

func pendingInstaller(agentDelay, menuDelay int) (*Installer, *removingLaunchd) {
	base := newFakeLaunchd()
	base.JobExports = true
	base.Loaded[agent.Label] = "/previous-agent.plist"
	base.Loaded[CompanionLabel] = "/previous-menu.plist"
	runner := &removingLaunchd{base: base, remaining: map[string]int{agent.Label: agentDelay, CompanionLabel: menuDelay}}
	fs := newMemFS()
	fs.files[companionExe] = []byte("executable")
	installer := newInstaller(base, fs)
	installer.Launchctl.Runner = runner
	return installer, runner
}

func TestInstallConfirmsBothAsyncRemovalsBeforeBootstrap(t *testing.T) {
	installer, runner := pendingInstaller(2, 4)
	sleeps := 0
	installer.Sleep = func(d time.Duration) {
		if d != 200*time.Millisecond {
			t.Fatalf("unexpected lifecycle interval: %s", d)
		}
		sleeps++
	}
	result, err := installer.Install(context.Background(), appExe, agent.RequireForce)
	if err != nil || result == nil || !result.CompanionManaged {
		t.Fatalf("Install: %+v %v", result, err)
	}
	if runner.early || len(runner.remaining) != 0 || sleeps != 6 {
		t.Fatalf("async removal was not fully observed: early=%v remaining=%v waits=%d", runner.early, runner.remaining, sleeps)
	}
}

func TestInstallNeverBootstrapsAfterRemovalFailure(t *testing.T) {
	for _, failure := range []string{"agent timeout", "menu timeout", "unexpected print error", "cancelled"} {
		t.Run(failure, func(t *testing.T) {
			installer, runner := pendingInstaller(0, 0)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var want error
			sleeps := 0
			installer.Sleep = func(time.Duration) { sleeps++ }
			switch failure {
			case "agent timeout":
				runner.remaining[agent.Label] = 1000
			case "menu timeout":
				runner.remaining[CompanionLabel] = 1000
			case "unexpected print error":
				want = &launchd.ExitError{Code: 1, Output: "unexpected print failure"}
				runner.printError = want
			case "cancelled":
				want = context.Canceled
				runner.onPrint = cancel
			}
			_, err := installer.Install(ctx, appExe, agent.RequireForce)
			if err == nil || (want != nil && !errors.Is(err, want)) {
				t.Fatalf("removal failure did not propagate: %v, want %v", err, want)
			}
			for _, call := range runner.base.Calls {
				if strings.HasPrefix(call, "bootstrap ") {
					t.Fatalf("failed removal bootstrapped a replacement: %s", call)
				}
			}
			if strings.Contains(failure, "timeout") && sleeps != 25 {
				t.Fatalf("changed existing wait budget: got %d, want 25", sleeps)
			}
			if want != nil && sleeps != 0 {
				t.Fatal("error or cancellation waited instead of failing immediately")
			}
		})
	}
}
