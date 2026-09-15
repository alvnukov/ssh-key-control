package proc_test

import (
	"testing"
	"time"

	"github.com/alvnukov/ssh-key-control/internal/proc"
)

var now = time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)

// link builds one process: how long ago it started, and which terminal it is
// attached to. A negative tty means the kernel would not say.
func link(pid int32, name string, ago time.Duration, tty int64) proc.Link {
	l := proc.Link{PID: pid, Version: uint32(pid) * 7, Name: name, Path: "/bin/" + name, Start: now.Add(-ago)}
	if tty >= 0 {
		l.TTY, l.TTYKnown = uint32(tty), true
	}
	return l
}

const (
	pane    = 16777220 // A terminal: ssh and the shell running it share one.
	noTTY   = int64(proc.NoTTY)
	unknown = int64(-1)
)

func TestBoundaryPicksTheNearestDurableAncestor(t *testing.T) {
	for _, tc := range []struct {
		name  string
		chain proc.Chain
		want  string // The Name of the boundary link, empty for no anchor.
	}{{
		name: "terminal running a shell",
		// The age of the shell finds it before the terminal's own window does.
		chain: proc.Chain{Complete: true, Links: []proc.Link{
			link(900, "ssh", 0, pane),
			link(800, "zsh", 90*time.Minute, pane),
			link(700, "login", 90*time.Minute, unknown),
			link(600, "iTerm2", 28*time.Hour, noTTY),
		}},
		want: "zsh",
	}, {
		name: "agent running commands in throwaway shells",
		// Nothing here has a terminal, so only the ages say anything.
		chain: proc.Chain{Complete: true, Links: []proc.Link{
			link(900, "ssh", 0, noTTY),
			link(850, "zsh", 0, noTTY),
			link(800, "claude.exe", 106*time.Minute, pane),
			link(700, "zsh", 107*time.Minute, pane),
			link(600, "iTerm2", 28*time.Hour, noTTY),
		}},
		want: "claude.exe",
	}, {
		name: "freshly opened pane where every process is a second old",
		// No age difference at all: the terminal signal still finds an anchor
		// rather than giving up and leasing to the whole machine.
		chain: proc.Chain{Complete: true, Links: []proc.Link{
			link(900, "ssh", 1100*time.Millisecond, pane),
			link(880, "zsh", 1100*time.Millisecond, pane),
			link(500, "tmux", 1100*time.Millisecond, noTTY),
		}},
		want: "tmux",
	}, {
		name: "editor with no terminal at all",
		chain: proc.Chain{Complete: true, Links: []proc.Link{
			link(900, "ssh", 0, noTTY),
			link(400, "Code Helper", 3*time.Hour, noTTY),
			link(300, "Electron", 3*time.Hour, noTTY),
		}},
		want: "Code Helper",
	}, {
		name:  "the caller alone",
		chain: proc.Chain{Complete: true, Links: []proc.Link{link(900, "ssh", 0, noTTY)}},
		want:  "",
	}, {
		name: "nothing tells them apart but the walk finished",
		chain: proc.Chain{Complete: true, Links: []proc.Link{
			link(900, "ssh", time.Minute, noTTY),
			link(800, "sh", 70*time.Second, noTTY),
			link(700, "launcher", 80*time.Second, noTTY),
		}},
		want: "launcher",
	}, {
		name: "nothing tells them apart and a parent was unreadable",
		chain: proc.Chain{Links: []proc.Link{
			link(900, "ssh", time.Minute, noTTY),
			link(800, "sh", 70*time.Second, noTTY),
		}},
		want: "",
	}} {
		t.Run(tc.name, func(t *testing.T) {
			at, ok := tc.chain.Boundary(now)
			if !ok {
				if tc.want != "" {
					t.Fatalf("no anchor found, want %s", tc.want)
				}
				return
			}
			if tc.want == "" {
				t.Fatalf("anchored at %s, want no anchor", tc.chain.Links[at].Name)
			}
			if got := tc.chain.Links[at].Name; got != tc.want {
				t.Fatalf("anchored at %s, want %s", got, tc.want)
			}
		})
	}
}

func TestBoundaryNeverInventsAnAgeItWasNotGiven(t *testing.T) {
	// login is owned by root, so its start time is withheld. Read as "very
	// old" it would anchor there; the shell above it is the honest answer.
	chain := proc.Chain{Complete: true, Links: []proc.Link{
		{PID: 900, Name: "ssh", Start: now, TTY: pane, TTYKnown: true},
		{PID: 800, Name: "login", TTY: pane, TTYKnown: true},
		{PID: 700, Name: "zsh", Start: now.Add(-time.Hour), TTY: pane, TTYKnown: true},
	}}
	at, ok := chain.Boundary(now)
	if !ok || chain.Links[at].Name != "zsh" {
		t.Fatalf("anchored at %d (%t), want the shell above the unreadable link", at, ok)
	}
}

func TestBoundaryIgnoresAMomentaryAgeGap(t *testing.T) {
	// Sixteen times older, but eighty milliseconds apart: both were started
	// by the same command, and neither will outlive it.
	chain := proc.Chain{Complete: true, Links: []proc.Link{
		link(900, "ssh", 5*time.Millisecond, noTTY),
		link(800, "sh", 80*time.Millisecond, noTTY),
		link(700, "make", 4*time.Hour, noTTY),
	}}
	at, _ := chain.Boundary(now)
	if chain.Links[at].Name != "make" {
		t.Fatalf("anchored at %s, want make", chain.Links[at].Name)
	}
}

func TestFingerprintTellsProcessesApart(t *testing.T) {
	base := proc.Chain{Links: []proc.Link{link(800, "zsh", time.Hour, pane), link(600, "iTerm2", time.Hour, noTTY)}}
	same := proc.Chain{Links: []proc.Link{link(800, "zsh", time.Hour, pane), link(600, "iTerm2", time.Hour, noTTY)}}
	if base.Fingerprint() != same.Fingerprint() {
		t.Fatal("the same two processes fingerprinted differently")
	}
	for _, tc := range []struct {
		name  string
		alter func(proc.Chain) proc.Chain
	}{
		{"a replaced image", func(c proc.Chain) proc.Chain { c.Links[0].Version++; return c }},
		{"a recycled pid", func(c proc.Chain) proc.Chain { c.Links[0].PID++; return c }},
		{"a shorter chain", func(c proc.Chain) proc.Chain { c.Links = c.Links[:1]; return c }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			altered := tc.alter(proc.Chain{Links: append([]proc.Link(nil), base.Links...)})
			if altered.Fingerprint() == base.Fingerprint() {
				t.Fatalf("%s kept the same fingerprint", tc.name)
			}
		})
	}
	if (proc.Chain{}).Fingerprint() != "" {
		t.Fatal("an unknown chain produced a fingerprint")
	}
}

func TestUnversionedLinkIsPinnedByName(t *testing.T) {
	root := func(name string) proc.Chain {
		return proc.Chain{Links: []proc.Link{link(800, "zsh", time.Hour, pane), {PID: 700, Name: name}}}
	}
	if root("login").Fingerprint() == root("sshd").Fingerprint() {
		t.Fatal("a pid the kernel would not version was matched on its number alone")
	}
}

func TestAnchorIsTheBoundaryAndEverythingAboveIt(t *testing.T) {
	chain := proc.Chain{Complete: true, Links: []proc.Link{
		link(900, "ssh", 0, pane), link(800, "zsh", time.Hour, pane), link(600, "iTerm2", 28*time.Hour, noTTY),
	}}
	anchor := chain.Anchor(1)
	if len(anchor.Links) != 2 || anchor.Links[0].Name != "zsh" {
		t.Fatalf("anchor = %+v", anchor.Links)
	}
	if !chain.Anchor(len(chain.Links)).Empty() || !chain.Anchor(-1).Empty() {
		t.Fatal("an out-of-range boundary produced an anchor")
	}
}

func TestDisplayPrefersTheExecutableAndFallsBackToTheKernelName(t *testing.T) {
	if got := (proc.Link{Name: "claude.exe", Path: "/opt/tools/claude"}).Display(); got != "claude" {
		t.Fatalf("Display = %q", got)
	}
	if got := (proc.Link{Name: "claude.exe"}).Display(); got != "claude.exe" {
		t.Fatalf("Display without a path = %q", got)
	}
}
